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
from .live_sources import readiness, select_sources, SOURCE_TOOLS


TOOLS = ("dns.lookup", "rdap.lookup", "archive.lookup", "search.execute", "ip.lookup", "registry.lookup", "vulnerability.lookup", "package.lookup", "evidence.retrieve")
ACTIONS = ("request_collection", "propose_observation", "propose_claim")


def add_workforce_parser(sub) -> None:
    root = sub.add_parser("workforce", help="Bounded hybrid AI workforce; disabled unless explicitly enabled")
    commands = root.add_subparsers(dest="workforce_command", required=True)
    commands.add_parser("registry", help="List the five initial employee definitions")
    sources = commands.add_parser("sources", help="Inspect source capabilities, health and secret-safe configuration")
    sources.add_argument("--catalog", action="store_true", help="Include all registered sources and truthful state counts")
    sources.add_argument("--capability", help="Filter the catalog by capability")
    sources.add_argument("--describe", help="Describe one registered source")
    sources.add_argument("--candidates", action="store_true", help="Show non-executable discovery candidates")
    authorize = commands.add_parser("authorize-domain", help="Register an immutable local owned-domain authority")
    authorize.add_argument("--case", required=True)
    authorize.add_argument("--domain", required=True)
    authorize.add_argument("--actor", required=True)
    authorize.add_argument("--purpose", required=True)
    authorize.add_argument("--jurisdiction", required=True)
    authorize.add_argument("--retention", default="case-standard")
    authorize.add_argument("--hours", type=int, default=24)
    authorize.add_argument("--authorized", action="store_true")
    auth = commands.add_parser("authorize", help="Register exact authority for a supported typed investigation seed")
    for option in ("case", "target", "actor", "purpose", "jurisdiction"):
        auth.add_argument("--" + option, required=True)
    auth.add_argument("--target-type", choices=("domain", "ip", "person", "company", "cve", "vulnerability", "package"), required=True)
    auth.add_argument("--retention", default="case-standard")
    auth.add_argument("--hours", type=int, default=24)
    auth.add_argument("--authorized", action="store_true")
    generic = commands.add_parser("plan", help="Plan a bounded typed investigation")
    generic.add_argument("--context", required=True)
    generic.add_argument("--target-type", choices=("domain", "ip", "person", "company", "cve", "vulnerability", "package"), required=True)
    generic.add_argument("--target", required=True)
    generic.add_argument("--objective", required=True)
    generic.add_argument("--sources", nargs="+", help="Bind explicit source IDs into the immutable approved task")
    generic.add_argument("--capabilities", nargs="+", help="Required intelligence capabilities; router chooses sources")
    generic.add_argument("--health-probe", action="store_true", help="Plan a fresh, separately approved canary for one explicit source")
    generic.add_argument("--source-price", action="append", default=[], metavar="SOURCE=USD",
                         help="Operator-approved per-request estimate for an account-priced source")
    collect = commands.add_parser("run", help="Execute approved collection, verification and draft reporting")
    collect.add_argument("--task", required=True)
    modes = collect.add_mutually_exclusive_group(required=True)
    modes.add_argument("--documents", type=Path, help="Approved source-document JSON")
    modes.add_argument("--live", action="store_true", help="Collect live sources bound into the approved typed task")
    collect.add_argument("--authorized", action="store_true")
    replay = commands.add_parser("replay", help="Verify and reanalyse captured bytes without network/model calls")
    replay.add_argument("--task", required=True)
    report = commands.add_parser("report", help="Return immutable investigation draft")
    report.add_argument("--task", required=True)
    golden = commands.add_parser("golden", help="Execute controlled end-to-end investigations")
    golden.add_argument("--source-fabric", action="store_true", help="Execute 78 Source Fabric fixture investigations")
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
        if args.source_fabric:
            from .source_golden import evaluate_source_fabric
            return evaluate_source_fabric()
        from .golden import evaluate_pipeline_investigations
        return evaluate_pipeline_investigations()
    if args.workforce_command == "sources":
        from .source_registry import SourceRegistry, P0_IDS
        from .source_state import SourceState
        registry = SourceRegistry()
        state = SourceState(WorkforceService(engine.db).store)
        if args.candidates:
            from .source_discovery import candidate_catalog
            return candidate_catalog()
        if args.describe:
            return {"manifest": registry.get(args.describe).to_dict(), "health": state.health(args.describe)}
        if args.catalog or args.capability:
            rows = [r.to_dict() for r in registry.list() if not args.capability or args.capability in r.capabilities]
            from ..source_maturity import MATURITY_STATES, maturity_counts
            return {"sources": rows, "capabilities": registry.capabilities(), "registered": len(registry.list()),
                    "canonical_adapters": len(P0_IDS), "production_qualified": 0,
                    "maturity_counts": maturity_counts(r.to_dict()["maturity_state"] for r in registry.list()),
                    "maturity_state_vocabulary": list(MATURITY_STATES),
            lifecycle_counts = registry.lifecycle_counts()
            live_count = len(registry.live_integrations())
            return {"sources": rows, "capabilities": registry.capabilities(), "registered": len(registry.list()),
                    "canonical_adapters": len(P0_IDS), "lifecycle_counts": lifecycle_counts,
                    "live_integrations": live_count,
                    "production_qualified": lifecycle_counts["PRODUCTION_QUALIFIED"],
                    "health": {r['source_id']: state.health(r['source_id']) for r in rows}, "network_requests": 0}
        return {"sources": readiness(), "network_requests": 0, "configuration_is_not_live_validation": True}
    service = WorkforceService(engine.db)
    if args.workforce_command in {"authorize-domain", "authorize"}:
        if not args.authorized:
            raise ValueError("authority registration requires explicit --authorized confirmation")
        if not 1 <= args.hours <= 168:
            raise ValueError("authorization duration must be 1-168 hours")
        kind = "domain" if args.workforce_command == "authorize-domain" else args.target_type
        domain = normalize_seed(kind, args.domain if kind == "domain" and args.workforce_command == "authorize-domain" else args.target)
        now = datetime.now(timezone.utc)
        from .source_registry import SourceRegistry, P0_IDS
        registry = SourceRegistry()
        effective_tools = tuple(sorted({"evidence.retrieve"} | {SOURCE_TOOLS[source] for source in P0_IDS if registry.supports(source, kind, domain)}))
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
        prices = {}
        for entry in args.source_price:
            source, value = entry.split('=', 1)
            if source in prices:
                raise ValueError('duplicate source price')
            prices[source] = float(value)
        return service.create_investigation_task(args.context, args.target_type, args.target, args.objective,
            sources=args.sources, capabilities=args.capabilities, source_prices=prices, health_probe=args.health_probe)
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
