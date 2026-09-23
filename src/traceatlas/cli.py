from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from . import __version__
from .engine import Engine
from .evidence import EvidenceStore
from .playbooks import METHODS, get_method
from .policy import PolicyError, validate_target
from .report import write_reports
from .spider import SpiderEngine
from .spider.export import export_scan
from .spider.modules import MODULES
from .integrations import CatalogStore, IntegrationRunner, PROFILES, TOOLS
from .sensitive import SensitiveRunner


CASE_ID = re.compile(r"^[a-zA-Z0-9_-]{2,64}$")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="traceatlas", description="Evidence-first OSINT automation")
    root.add_argument("--workspace", type=Path, default=Path("cases"))
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command", required=True)

    methods = sub.add_parser("methods", help="List or inspect the 40 playbooks")
    methods.add_argument("method", nargs="?")
    methods.add_argument("--json", action="store_true")

    init = sub.add_parser("init", help="Create a case")
    init.add_argument("case_id")
    init.add_argument("--title", required=True)
    init.add_argument("--purpose", required=True)

    run = sub.add_parser("run", help="Run one playbook")
    run.add_argument("--case", required=True)
    run.add_argument("--method", required=True)
    run.add_argument("--target-type", required=True, choices=[
        "url", "domain", "ip", "email", "username", "file", "phone", "crypto", "text"
    ])
    run.add_argument("--target", required=True)
    run.add_argument("--authorized", action="store_true")

    report = sub.add_parser("report", help="Generate JSON and Markdown case reports")
    report.add_argument("--case", required=True)
    report.add_argument("--output", type=Path, default=Path("reports"))

    verify = sub.add_parser("verify", help="Verify a case evidence ledger")
    verify.add_argument("--case", required=True)

    monitor = sub.add_parser("monitor", help="Run a method and record whether results changed")
    monitor.add_argument("--case", required=True)
    monitor.add_argument("--method", required=True)
    monitor.add_argument("--target-type", required=True)
    monitor.add_argument("--target", required=True)
    monitor.add_argument("--authorized", action="store_true")

    spider = sub.add_parser("spider", help="Event-driven SpiderFoot-style correlation engine")
    spider_sub = spider.add_subparsers(dest="spider_command", required=True)
    spider_modules = spider_sub.add_parser("modules", help="List event modules")
    spider_modules.add_argument("--json", action="store_true")
    spider_scan = spider_sub.add_parser("scan", help="Run a bounded passive event scan")
    spider_scan.add_argument("--case", required=True)
    spider_scan.add_argument("--seed-type", required=True, choices=[
        "domain", "url", "ip", "email", "username", "file", "text"
    ])
    spider_scan.add_argument("--seed", required=True)
    spider_scan.add_argument("--modules", help="Comma-separated module allowlist")
    spider_scan.add_argument("--max-events", type=int, default=250)
    spider_scan.add_argument("--max-depth", type=int, default=3)
    spider_scan.add_argument("--authorized", action="store_true")
    spider_events = spider_sub.add_parser("events", help="Print stored events for a scan")
    spider_events.add_argument("--scan", required=True)
    spider_export = spider_sub.add_parser("export", help="Export a scan graph")
    spider_export.add_argument("--scan", required=True)
    spider_export.add_argument("--format", choices=["json", "gexf"], default="json")
    spider_export.add_argument("--output", type=Path, required=True)

    integrations = sub.add_parser("integrations", help="Manage external OSINT/recon tool adapters")
    int_sub = integrations.add_subparsers(dest="integration_command", required=True)
    int_list = int_sub.add_parser("list", help="List supported tools and installation state")
    int_list.add_argument("--json", action="store_true")
    int_list.add_argument("--installed", action="store_true")
    int_show = int_sub.add_parser("show", help="Inspect one adapter")
    int_show.add_argument("tool", choices=sorted(TOOLS))
    int_doctor = int_sub.add_parser("doctor", help="Summarize integration readiness")
    int_doctor.add_argument("--json", action="store_true")
    int_run = int_sub.add_parser("run", help="Run one managed external tool")
    int_run.add_argument("--case", required=True)
    int_run.add_argument("--tool", required=True, choices=sorted(TOOLS))
    int_run.add_argument("--target-type", required=True, choices=[
        "url", "domain", "ip", "email", "username", "file", "path", "text"
    ])
    int_run.add_argument("--target", required=True)
    int_run.add_argument("--authorized", action="store_true")
    int_run.add_argument("--allow-active", action="store_true")
    int_run.add_argument("--tool-option", action="append", default=[], metavar="KEY=VALUE")
    int_run.add_argument("--timeout", type=int)
    int_profile = int_sub.add_parser("profile", help="Run every installed compatible tool in a profile")
    int_profile.add_argument("profile", choices=sorted(PROFILES))
    int_profile.add_argument("--case", required=True)
    int_profile.add_argument("--target-type", required=True, choices=[
        "url", "domain", "ip", "email", "username", "file", "path", "text"
    ])
    int_profile.add_argument("--target", required=True)
    int_profile.add_argument("--authorized", action="store_true")
    int_profile.add_argument("--allow-active", action="store_true")
    int_profile.add_argument("--tool-option", action="append", default=[], metavar="KEY=VALUE")
    int_catalog_import = int_sub.add_parser("catalog-import", help="Import JSON, JSON.GZ or embedded HTML tool data")
    int_catalog_import.add_argument("--file", type=Path, required=True)
    int_catalog_search = int_sub.add_parser("catalog-search", help="Search imported web/tool directory entries")
    int_catalog_search.add_argument("query", nargs="?", default="")
    int_catalog_search.add_argument("--category")
    int_catalog_search.add_argument("--limit", type=int, default=50)
    int_catalog_stats = int_sub.add_parser("catalog-stats", help="Show imported catalog coverage")
    int_pipeline = int_sub.add_parser("pipeline", help="Discover a domain, then optionally validate assets")
    int_pipeline.add_argument("--case", required=True)
    int_pipeline.add_argument("--domain", required=True)
    int_pipeline.add_argument("--authorized", action="store_true")
    int_pipeline.add_argument("--verify", action="store_true")
    int_pipeline.add_argument("--allow-active", action="store_true")
    int_pipeline.add_argument("--max-assets", type=int, default=25)

    sensitive = sub.add_parser(
        "sensitive", help="Run explicitly authorized, redacted sensitive-data workflows"
    )
    sensitive_sub = sensitive.add_subparsers(dest="sensitive_command", required=True)

    def add_sensitive_common(command: argparse.ArgumentParser) -> None:
        command.add_argument("--case", required=True)
        command.add_argument("--lawful-purpose", required=True)
        command.add_argument("--authorized", action="store_true")
        command.add_argument("--allow-sensitive", action="store_true")

    darkweb = sensitive_sub.add_parser(
        "darkweb-monitor", help="Search Ahmia's clear-web index without fetching onion services"
    )
    add_sensitive_common(darkweb)
    darkweb.add_argument("--domain", required=True)
    darkweb.add_argument("--owned-domain", action="store_true")
    darkweb_source = darkweb.add_mutually_exclusive_group(required=True)
    darkweb_source.add_argument(
        "--index-file", type=Path,
        help="Approved Ahmia/provider HTML export to parse without network access",
    )
    darkweb_source.add_argument(
        "--live-ahmia", action="store_true",
        help="Use Ahmia clear-web search only when source permission is documented",
    )
    darkweb.add_argument("--authorized-feed", action="store_true")
    darkweb.add_argument("--source-permission", action="store_true")

    breach_catalog = sensitive_sub.add_parser(
        "breach-catalog", help="Collect public breach metadata for an owned domain"
    )
    add_sensitive_common(breach_catalog)
    breach_catalog.add_argument("--domain", required=True)
    breach_catalog.add_argument("--owned-domain", action="store_true")

    breach_domain = sensitive_sub.add_parser(
        "breach-domain", help="Check aliases for a domain verified in HIBP"
    )
    add_sensitive_common(breach_domain)
    breach_domain.add_argument("--domain", required=True)
    breach_domain.add_argument("--owned-domain", action="store_true")
    breach_domain.add_argument("--hibp-domain-verified", action="store_true")

    breach_account = sensitive_sub.add_parser(
        "breach-account", help="Check a consenting account with HIBP email k-anonymity"
    )
    add_sensitive_common(breach_account)
    breach_account.add_argument("--email", required=True)
    breach_account.add_argument("--subject-consent", action="store_true")

    password_hash = sensitive_sub.add_parser(
        "password-hash", help="Check an owned account's SHA-1 hash; plaintext is rejected"
    )
    add_sensitive_common(password_hash)
    password_hash.add_argument("--sha1", required=True)
    password_hash.add_argument("--owned-account", action="store_true")

    person = sensitive_sub.add_parser(
        "person-profile", help="Find consented public professional-profile candidates"
    )
    add_sensitive_common(person)
    person.add_argument("--name", required=True)
    person.add_argument("--subject-consent", action="store_true")

    wifi = sensitive_sub.add_parser(
        "wifi-locate", help="Look up an owned BSSID and retain only coarse location"
    )
    add_sensitive_common(wifi)
    wifi.add_argument("--bssid", required=True)
    wifi.add_argument("--owned-asset", action="store_true")

    artifact = sensitive_sub.add_parser(
        "breach-artifact", help="Summarize an authorized local breach file without copying rows"
    )
    add_sensitive_common(artifact)
    artifact.add_argument("--file", type=Path, required=True)
    artifact.add_argument("--authorized-data", action="store_true")
    return root


def _key_values(items: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise PolicyError(f"Tool option must use KEY=VALUE: {item}")
        key, value = item.split("=", 1)
        key = key.strip().lower()
        if not key or key not in {"module", "wordlist", "resolvers"}:
            raise PolicyError(f"Unsupported tool option: {key or '<empty>'}")
        result[key] = value.strip()
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "methods":
        selected = [get_method(args.method)] if args.method is not None else list(METHODS)
        if args.json:
            print(json.dumps([m.to_dict() for m in selected], indent=2))
        else:
            for method in selected:
                print(f"{method.id:02d}  {method.slug:24} {method.automation:9} {method.title}")
        return 0
    engine = Engine(args.workspace)
    try:
        if args.command == "init":
            if not CASE_ID.fullmatch(args.case_id):
                raise PolicyError("Case ID must be 2-64 letters, digits, underscores or hyphens")
            engine.db.create_case(args.case_id, args.title, args.purpose)
            print(json.dumps({"case_id": args.case_id, "status": "created"}))
        elif args.command == "run":
            result = engine.run(args.case, args.method, args.target_type, args.target, args.authorized)
            print(json.dumps(result, indent=2))
        elif args.command == "report":
            paths = write_reports(engine.db, args.case, args.output)
            print(json.dumps({"json": str(paths[0]), "markdown": str(paths[1])}, indent=2))
        elif args.command == "verify":
            ok, entries = EvidenceStore(args.workspace, engine.db, args.case).verify_ledger()
            print(json.dumps({"valid": ok, "entries": entries}))
            return 0 if ok else 2
        elif args.command == "monitor":
            result = engine.run(args.case, args.method, args.target_type, args.target, args.authorized)
            payload = engine.db.findings(args.case)
            # Exclude volatile IDs/timestamps/run IDs. An unchanged collection must
            # not produce a false alert merely because it ran at a new time.
            stable_payload = [
                {key: item[key] for key in (
                    "title", "value", "source", "confidence", "severity", "observation"
                )}
                for item in payload
            ]
            digest = hashlib.sha256(
                json.dumps(stable_payload, sort_keys=True, default=str).encode()
            ).hexdigest()
            key = f"{args.method}:{args.target_type}:{args.target}"
            result["changed"] = engine.db.snapshot(args.case, key, digest, stable_payload)
            print(json.dumps(result, indent=2))
        elif args.command == "spider":
            if args.spider_command == "modules":
                rows = [{
                    "name": module.name, "description": module.description,
                    "watches": sorted(module.watches), "produces": sorted(module.produces),
                    "passive": module.passive,
                } for module in MODULES.values()]
                if args.json:
                    print(json.dumps(rows, indent=2))
                else:
                    for row in rows:
                        print(f"{row['name']:18} {','.join(row['watches']):24} {row['description']}")
            elif args.spider_command == "scan":
                if args.seed_type not in {"file", "text"} and not args.authorized:
                    raise PolicyError("Network and identity seeds require explicit --authorized confirmation")
                validate_target(args.seed_type, args.seed)
                kind_map = {"ip": "IP_ADDRESS", "email": "EMAIL_ADDRESS"}
                seed_type = kind_map.get(args.seed_type, args.seed_type.upper())
                modules = args.modules.split(",") if args.modules else None
                result = SpiderEngine(engine.db).scan(
                    args.case, seed_type, args.seed, enabled_modules=modules,
                    max_events=args.max_events, max_depth=args.max_depth,
                )
                print(json.dumps(result, indent=2))
            elif args.spider_command == "events":
                events = engine.db.spider_events(args.scan)
                if not engine.db.spider_scan(args.scan):
                    raise ValueError(f"Unknown spider scan: {args.scan}")
                print(json.dumps(events, indent=2))
            elif args.spider_command == "export":
                path = export_scan(engine.db, args.scan, args.output, args.format)
                print(json.dumps({"output": str(path), "format": args.format}))
        elif args.command == "integrations":
            runner = IntegrationRunner(engine.db, args.workspace)
            if args.integration_command == "list":
                rows = runner.inventory()
                if args.installed:
                    rows = [row for row in rows if row["installed"]]
                if args.json:
                    print(json.dumps(rows, indent=2))
                else:
                    for row in rows:
                        state = "BLOCKED" if row["mode"] == "blocked" else "READY" if row["installed"] else "MISSING"
                        print(f"{row['name']:15} {state:8} {row['mode']:8} {row['description']}")
            elif args.integration_command == "show":
                row = next(item for item in runner.inventory() if item["name"] == args.tool)
                print(json.dumps(row, indent=2))
            elif args.integration_command == "doctor":
                rows = runner.inventory()
                summary = {
                    "supported": len(rows),
                    "executable_adapters": sum(row["executable"] for row in rows),
                    "installed": sum(row["installed"] and row["executable"] for row in rows),
                    "missing": [row["name"] for row in rows if row["executable"] and not row["installed"]],
                    "blocked": [row["name"] for row in rows if not row["executable"]],
                    "profiles": {name: list(tools) for name, tools in PROFILES.items()},
                }
                if args.json:
                    print(json.dumps(summary, indent=2))
                else:
                    print(f"Supported: {summary['supported']}")
                    print(f"Executable adapters: {summary['executable_adapters']}")
                    print(f"Installed and ready: {summary['installed']}")
                    print("Missing: " + (", ".join(summary["missing"]) or "none"))
                    print("Blocked by policy: " + ", ".join(summary["blocked"]))
            elif args.integration_command == "run":
                result = runner.run(
                    args.case, args.tool, args.target_type, args.target,
                    authorized=args.authorized, allow_active=args.allow_active,
                    options=_key_values(args.tool_option), timeout=args.timeout,
                )
                print(json.dumps(result, indent=2))
            elif args.integration_command == "profile":
                result = runner.run_profile(
                    args.case, args.profile, args.target_type, args.target,
                    authorized=args.authorized, allow_active=args.allow_active,
                    options=_key_values(args.tool_option),
                )
                print(json.dumps(result, indent=2))
            elif args.integration_command == "catalog-import":
                result = CatalogStore(args.workspace).import_file(args.file)
                print(json.dumps(result, indent=2))
            elif args.integration_command == "catalog-search":
                results = CatalogStore(args.workspace).search(args.query, args.category, args.limit)
                print(json.dumps(results, indent=2))
            elif args.integration_command == "catalog-stats":
                print(json.dumps(CatalogStore(args.workspace).stats(), indent=2))
            elif args.integration_command == "pipeline":
                result = runner.run_domain_pipeline(
                    args.case, args.domain, authorized=args.authorized,
                    verify=args.verify, allow_active=args.allow_active,
                    max_assets=args.max_assets,
                )
                print(json.dumps(result, indent=2))
        elif args.command == "sensitive":
            runner = SensitiveRunner(engine.db, args.workspace)
            common = {
                "lawful_purpose": args.lawful_purpose,
                "authorized": args.authorized,
                "allow_sensitive": args.allow_sensitive,
            }
            if args.sensitive_command == "darkweb-monitor":
                result = runner.darkweb_monitor(
                    args.case, args.domain, owned_domain=args.owned_domain,
                    index_file=args.index_file, live_ahmia=args.live_ahmia,
                    authorized_feed=args.authorized_feed,
                    source_permission=args.source_permission, **common,
                )
            elif args.sensitive_command == "breach-catalog":
                result = runner.breach_catalog(
                    args.case, args.domain, owned_domain=args.owned_domain, **common
                )
            elif args.sensitive_command == "breach-domain":
                result = runner.breach_domain(
                    args.case, args.domain, owned_domain=args.owned_domain,
                    hibp_domain_verified=args.hibp_domain_verified, **common,
                )
            elif args.sensitive_command == "breach-account":
                result = runner.breach_account(
                    args.case, args.email, subject_consent=args.subject_consent, **common
                )
            elif args.sensitive_command == "password-hash":
                result = runner.password_hash_check(
                    args.case, args.sha1, owned_account=args.owned_account, **common
                )
            elif args.sensitive_command == "person-profile":
                result = runner.person_profile(
                    args.case, args.name, subject_consent=args.subject_consent, **common
                )
            elif args.sensitive_command == "wifi-locate":
                result = runner.wifi_locate(
                    args.case, args.bssid, owned_asset=args.owned_asset, **common
                )
            elif args.sensitive_command == "breach-artifact":
                result = runner.breach_artifact(
                    args.case, args.file, authorized_data=args.authorized_data, **common
                )
            print(json.dumps(result, indent=2))
        return 0
    except (PolicyError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        engine.close()


if __name__ == "__main__":
    raise SystemExit(main())
