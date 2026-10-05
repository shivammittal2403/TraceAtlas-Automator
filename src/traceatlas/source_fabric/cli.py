from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from ..employee.service import ATTESTATIONS
from ..employee.brief import digest
from ..policy import PolicyError
from ..opencti_connectors import OpenCTIConnectorCatalog
from .registry import audit, candidates, manifest, SOURCES
from .router import SourceRouter
from .store import FabricStore, QUALIFICATION_CHECKS, utc


def add_fabric_parser(sub):
    root = sub.add_parser("source-fabric", help="Audit, qualify and route the source ecosystem")
    commands = root.add_subparsers(dest="fabric_command", required=True)
    commands.add_parser("audit")
    commands.add_parser("metrics")
    commands.add_parser("health", help="Observed per-source health, independent of maturity")
    integration = commands.add_parser("integration-review", help="Preserve a source-specific successful live integration receipt")
    integration.add_argument("--source", required=True, choices=sorted(SOURCES))
    integration.add_argument("--execution", required=True)
    integration.add_argument("--case", required=True)
    integration.add_argument("--actor", required=True)
    integration.add_argument("--authorized", action="store_true")
    portfolio = commands.add_parser("portfolio", help="Governed research and 650-source acceptance report")
    portfolio.add_argument("--file", type=Path, help="Import bounded research metadata; grants no execution")
    portfolio.add_argument("--source", help="Inspect every governed metadata field for one source")
    portfolio.add_argument("--html", type=Path, help="Export a self-contained read-only portfolio/health dashboard")
    portfolio.add_argument("--capability", action="append", help="Generate a non-executing four-wave plan")
    portfolio.add_argument("--country")
    portfolio.add_argument("--language")
    portfolio.add_argument("--budget", type=float, default=0)
    portfolio.add_argument("--max-sources", type=int, default=8)
    catalog = commands.add_parser("catalog")
    catalog.add_argument("query", nargs="?", default="")
    catalog.add_argument("--limit", type=int, default=30)
    show = commands.add_parser("manifest")
    show.add_argument("source", choices=sorted(SOURCES))
    plan = commands.add_parser("plan")
    plan.add_argument("--objective", required=True)
    plan.add_argument("--seed", required=True)
    plan.add_argument("--country")
    plan.add_argument("--language")
    for key in sorted(ATTESTATIONS):
        plan.add_argument("--"+key.replace("_", "-"), action="store_true")
    review = commands.add_parser("review", help="Record a source-bound qualification receipt")
    review.add_argument("--source", required=True, choices=sorted(SOURCES))
    review.add_argument("--check", required=True, choices=sorted(QUALIFICATION_CHECKS))
    review.add_argument("--case", required=True)
    review_input = review.add_mutually_exclusive_group(required=True)
    review_input.add_argument("--evidence-hash", help="Hash of a receipt already in case custody")
    review_input.add_argument("--receipt", type=Path, help="Preserve a completed receipt before review")
    review.add_argument("--actor", required=True)
    review.add_argument("--authorized", action="store_true")
    template = commands.add_parser("review-template", help="Create an incomplete source-bound review form")
    template.add_argument("--source", required=True, choices=sorted(SOURCES))
    template.add_argument("--check", required=True, choices=sorted(QUALIFICATION_CHECKS))
    template.add_argument("--case", required=True)
    template.add_argument("--actor", required=True)
    template.add_argument("--runtime-id", required=True)
    promotion = commands.add_parser("promote")
    promotion.add_argument("--source", required=True, choices=sorted(SOURCES))
    promotion.add_argument("--actor", required=True)
    promotion.add_argument("--authorized", action="store_true")
    discovery = commands.add_parser("discover", help="Stage new candidates without granting execution")
    inputs = discovery.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--file", type=Path, help="Bounded JSON list of candidate name/documentation_url records")
    inputs.add_argument("--opencti", action="store_true", help="Discover candidates from the pinned upstream package catalogue")


def run_fabric(args, engine):
    store = FabricStore(engine.db)
    if args.fabric_command == "integration-review":
        from .integration import IntegrationReceipts
        return IntegrationReceipts(engine.db, engine.workspace).record(
            args.source, args.execution, args.case, args.actor, authorized=args.authorized)
    if args.fabric_command == "health":
        from .portfolio import Portfolio
        return Portfolio(engine.db).health_report()
    if args.fabric_command == "portfolio":
        from .portfolio import Portfolio
        program = Portfolio(engine.db)
        if sum(bool(value) for value in (args.file, args.source, args.capability, args.html)) > 1:
            raise PolicyError("Choose one portfolio mode: import, inspect, plan or HTML snapshot")
        if args.html:
            from .dashboard import render_dashboard
            args.html.parent.mkdir(parents=True, exist_ok=True)
            args.html.write_text(render_dashboard(program.report(), program.records(), program.health_report()), encoding="utf-8")
            return {"dashboard": str(args.html.resolve()), "snapshot": True, "network_probes": 0}
        if args.file:
            if not args.file.is_file() or args.file.stat().st_size > 2*1024*1024:
                raise PolicyError("Research input must be a JSON file up to 2 MiB")
            return program.import_records(json.loads(args.file.read_text(encoding="utf-8")))
        if args.source:
            row = next((r for r in program.records() if r['source_id'] == args.source), None)
            if row is None:
                raise PolicyError("Unknown portfolio source")
            return row
        if args.capability:
            return program.rank(args.capability, country=args.country, language=args.language,
                                budget=args.budget, max_sources=args.max_sources)
        return program.report()
    if args.fabric_command == "audit":
        return audit(engine.db)
    if args.fabric_command == "metrics":
        return store.metrics()
    if args.fabric_command == "catalog":
        if not 1 <= args.limit <= 1000:
            raise PolicyError("Catalogue limit must be 1-1000")
        rows = candidates()+[json.loads(r[0]) for r in engine.db.conn.execute("SELECT manifest_json FROM fabric_candidates")]
        selected = [r for r in rows if args.query.casefold() in json.dumps(r).casefold()]
        return {"matching_candidate_slots": len(selected), "candidates": selected[:args.limit], "executable": False}
    if args.fabric_command == "manifest":
        result = manifest(args.source)
        result["implementation_status"] = store.states().get(args.source, result["implementation_status"])
        result["maturity_state"] = result["implementation_status"]
        return result
    if args.fabric_command == "plan":
        kind, separator, target = args.seed.partition(":")
        if not separator:
            raise PolicyError("Seed must be type:value")
        return SourceRouter(engine.db).plan(args.objective, kind, target,
            {key: getattr(args, key) for key in ATTESTATIONS}, country=args.country, language=args.language)
    if args.fabric_command == "review":
        evidence_hash = args.evidence_hash
        if args.receipt:
            from ..evidence import EvidenceStore
            from .review_receipts import MAX_RECEIPT_BYTES
            if args.authorized is not True:
                raise PolicyError("Explicit analyst authority is required before preserving a review receipt")
            if not args.receipt.is_file() or args.receipt.stat().st_size > MAX_RECEIPT_BYTES:
                raise PolicyError("Review receipt must be a file up to 64 KiB")
            evidence_hash = EvidenceStore(engine.workspace, engine.db, args.case).preserve_file(
                args.receipt, "source-qualification:" + args.source + ":" + args.check)["sha256"]
        store.review(args.source, args.check, args.case, evidence_hash, args.actor, engine.workspace, args.authorized)
        return {"source": args.source, "review_recorded": args.check, "evidence_hash": evidence_hash, "production_promoted": False}
    if args.fabric_command == "review-template":
        from .review_receipts import review_template
        return review_template(args.source, args.check, args.case, args.actor, args.runtime_id)
    if args.fabric_command == "promote":
        return store.promote(args.source, args.actor, engine.workspace, args.authorized)
    if args.opencti:
        rows = [{"name": row["title"], "upstream_package_id": row["id"], "documentation_url": None,
                 "origin": "pinned OpenCTI package catalogue; external-service candidate"}
                for row in OpenCTIConnectorCatalog().list(limit=1000)]
    else:
        if not args.file.is_file() or args.file.stat().st_size > 2*1024*1024:
            raise PolicyError("Discovery input must be a JSON file up to 2 MiB")
        rows = json.loads(args.file.read_text(encoding="utf-8"))
        if not isinstance(rows, list) or len(rows) > 1000:
            raise PolicyError("Discovery input must contain at most 1000 records")
    added = 0
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not 2 <= len(row["name"]) <= 200:
            raise PolicyError("Candidate name required")
        url = row.get("documentation_url")
        if url is not None:
            if not isinstance(url, str) or len(url) > 2000:
                raise PolicyError("Candidate documentation URL must be a bounded string")
            parsed = urlsplit(url)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise PolicyError("Candidate documentation link must be HTTPS; URLs are stored, never fetched by discovery")
        candidate = {"candidate_id": "discovered-"+digest([row["name"].casefold(), url])[:24],
                     "name": row["name"], "documentation_url": url, "implementation_status": "DISCOVERED",
                     "review_status": "UNREVIEWED", "origin": row.get("origin", "analyst-supplied candidate"),
                     "execution_path": None}
        cursor = engine.db.conn.execute("INSERT OR IGNORE INTO fabric_candidates VALUES(?,?,?)", (candidate["candidate_id"], json.dumps(candidate), utc()))
        added += cursor.rowcount
    engine.db.conn.commit()
    return {"staged_new_candidates": added, "execution_granted": False, "production_promoted": False}
