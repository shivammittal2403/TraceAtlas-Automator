from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from uuid import uuid4

from . import __version__
from .engine import Engine
from .evidence import EvidenceStore
from .playbooks import METHODS, get_method
from .policy import PolicyError, validate_target
from .report import write_reports
from .spider import SpiderEngine
from .spider.export import export_scan
from .spider.modules import MODULES
from .integrations import CatalogStore, IntegrationLock, IntegrationRunner, PROFILES, TOOLS
from .intelligence import IntelligenceAnalyzer, IntelligenceHub, MediaAnalyzer, SOURCES
from .sensitive import SensitiveRunner
from .openosint_bridge import OpenOSINTBridge
from .capabilities import CAPABILITIES, CapabilityHub, TrainingStore
from .cti import CTIEngine
from .fusion_board import FusionBoard, SCOPES
from .research_cli import add_research_parser, run_research
from .search_index import bm25_search
from .automation import AutomationManager
from .deployment import DeploymentDoctor
from .resolution import ResolutionService
from .models import utc_now
from .intelligence.sanitize import sanitize_text
from .readiness import ReadinessScorecard


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

    search = sub.add_parser("search", help="Search findings and events in one local case")
    search.add_argument("query")
    search.add_argument("--case", required=True)
    search.add_argument("--limit", type=int, default=20)

    verify = sub.add_parser("verify", help="Verify a case evidence ledger")
    verify.add_argument("--case", required=True)

    monitor = sub.add_parser("monitor", help="Run a method and record whether results changed")
    monitor.add_argument("--case", required=True)
    monitor.add_argument("--method", required=True)
    monitor.add_argument("--target-type", required=True)
    monitor.add_argument("--target", required=True)
    monitor.add_argument("--authorized", action="store_true")

    automation = sub.add_parser("automation", help="Manage durable local schedules and alerts")
    auto_sub = automation.add_subparsers(dest="automation_command", required=True)
    auto_add = auto_sub.add_parser("add", help="Create an authority-bound deterministic schedule")
    auto_add.add_argument("--case", required=True)
    auto_add.add_argument("--name", required=True)
    auto_add.add_argument("--method", required=True)
    auto_add.add_argument("--target-type", required=True, choices=[
        "url", "domain", "ip", "email", "username", "phone", "crypto", "text"
    ])
    auto_add.add_argument("--target", required=True)
    auto_add.add_argument("--every-minutes", required=True, type=int)
    auto_add.add_argument("--authority", required=True)
    auto_add.add_argument("--authorized", action="store_true")
    auto_list = auto_sub.add_parser("list", help="List persisted schedules")
    auto_list.add_argument("--case")
    auto_list.add_argument("--json", action="store_true")
    auto_due = auto_sub.add_parser("run-due", help="Claim and execute due schedules once")
    auto_due.add_argument("--limit", type=int, default=10)
    auto_history = auto_sub.add_parser("history", help="Show schedule execution history")
    auto_history.add_argument("--schedule")
    auto_history.add_argument("--limit", type=int, default=100)
    auto_alerts = auto_sub.add_parser("alerts", help="Show local change/failure alerts")
    auto_alerts.add_argument("--case")
    auto_alerts.add_argument("--open-only", action="store_true")
    auto_alerts.add_argument("--limit", type=int, default=100)
    auto_ack = auto_sub.add_parser("ack", help="Acknowledge one open alert")
    auto_ack.add_argument("--alert", required=True)
    for action in ("enable", "disable"):
        command = auto_sub.add_parser(action, help=f"{action.title()} one persisted schedule")
        command.add_argument("--schedule", required=True)

    deployment = sub.add_parser("deployment", help="Check repository and production readiness")
    deploy_sub = deployment.add_subparsers(dest="deployment_command", required=True)
    deploy_doctor = deploy_sub.add_parser("doctor", help="Run non-mutating deployment checks")
    deploy_doctor.add_argument("--production", action="store_true")
    deploy_doctor.add_argument("--json", action="store_true")

    readiness = sub.add_parser("readiness", help="Score verified core, production and competitive readiness")
    readiness.add_argument("--production", action="store_true")
    readiness.add_argument("--json", action="store_true")

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
    spider_export.add_argument("--format", choices=["json", "gexf", "html"], default="json")
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
    int_lock = int_sub.add_parser("lock", help="Hash-lock currently installed external binaries")
    int_lock.add_argument("--output", type=Path, default=Path(".traceatlas/integration-lock.json"))
    int_verify_lock = int_sub.add_parser("verify-lock", help="Detect missing, changed or untracked binaries")
    int_verify_lock.add_argument("--file", type=Path, default=Path(".traceatlas/integration-lock.json"))
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

    intel = sub.add_parser(
        "intel", help="Collect, ingest and analyse governed multi-source intelligence"
    )
    intel_sub = intel.add_subparsers(dest="intel_command", required=True)
    intel_sources = intel_sub.add_parser("sources", help="List supported intelligence sources")
    intel_sources.add_argument("--json", action="store_true")

    def add_intel_attestations(command: argparse.ArgumentParser) -> None:
        command.add_argument("--authorized", action="store_true")
        command.add_argument("--subject-consent", action="store_true")
        command.add_argument("--owned-org", action="store_true")
        command.add_argument("--owned-asset", action="store_true")
        command.add_argument("--public-record-basis", action="store_true")

    intel_ingest = intel_sub.add_parser(
        "ingest", help="Normalize an official, authoritative or otherwise approved export"
    )
    intel_ingest.add_argument("--case", required=True)
    intel_ingest.add_argument("--source", required=True, choices=sorted(SOURCES))
    intel_ingest.add_argument("--file", type=Path, required=True)
    add_intel_attestations(intel_ingest)

    intel_collect = intel_sub.add_parser(
        "collect", help="Query a supported official/public API connector"
    )
    intel_collect.add_argument("--case", required=True)
    intel_collect.add_argument(
        "--source", required=True,
        choices=sorted(name for name, spec in SOURCES.items() if spec.live_connector),
    )
    intel_collect.add_argument(
        "--target-type", required=True,
        choices=["username", "channel", "invite", "ip", "domain", "url", "hash"],
    )
    intel_collect.add_argument("--target", required=True)
    add_intel_attestations(intel_collect)

    intel_media = intel_sub.add_parser(
        "media", help="Analyse authorised image, audio or video evidence locally"
    )
    intel_media.add_argument("--case", required=True)
    intel_media.add_argument("--file", type=Path, required=True)
    intel_media.add_argument("--authorized", action="store_true")
    intel_media.add_argument("--subject-consent", action="store_true")
    intel_media.add_argument("--owned-asset", action="store_true")
    intel_media.add_argument("--ocr", action="store_true")
    intel_media.add_argument("--transcribe", action="store_true")
    intel_media.add_argument("--whisper-model", default="tiny")
    intel_media.add_argument("--ollama", action="store_true")
    intel_media.add_argument("--model", default="llava:7b")
    intel_media.add_argument("--ollama-url", default="http://127.0.0.1:11434")

    intel_analyze = intel_sub.add_parser(
        "analyze", help="Create fact/inference-separated analysis of a stored scan"
    )
    intel_analyze.add_argument("--case", required=True)
    intel_analyze.add_argument("--scan", required=True)
    intel_analyze.add_argument("--authorized", action="store_true")
    intel_analyze.add_argument("--ollama", action="store_true")
    intel_analyze.add_argument("--model", default="qwen2.5:7b")
    intel_analyze.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    intel_analyze.add_argument("--output", type=Path)

    intel_doctor = intel_sub.add_parser("doctor", help="Show API and local media-analysis readiness")
    intel_doctor.add_argument("--json", action="store_true")
    intel_health = intel_sub.add_parser("health", help="Show live connector success/failure history")
    intel_health.add_argument("--json", action="store_true")

    upstream = sub.add_parser("openosint", help="Use the preserved OpenOSINT compatibility package")
    upstream_sub = upstream.add_subparsers(dest="openosint_command", required=True)
    upstream_doctor = upstream_sub.add_parser("doctor", help="Check bundled OpenOSINT readiness")
    upstream_doctor.add_argument("--json", action="store_true")
    upstream_run = upstream_sub.add_parser("run", help="Run an approved direct OpenOSINT command")
    upstream_run.add_argument("--case", required=True)
    upstream_run.add_argument("--authorized", action="store_true")
    upstream_run.add_argument("--subject-consent", action="store_true")
    upstream_run.add_argument("--owned-asset", action="store_true")
    upstream_run.add_argument("--timeout", type=int, default=300)
    upstream_run.add_argument("arguments", nargs=argparse.REMAINDER)

    capabilities = sub.add_parser(
        "capabilities", help="Inspect and ingest results from optional upstream engines"
    )
    cap_sub = capabilities.add_subparsers(dest="capability_command", required=True)
    cap_list = cap_sub.add_parser("list", help="List all governed upstream integrations")
    cap_list.add_argument("--json", action="store_true")
    cap_show = cap_sub.add_parser("show", help="Show one integration contract")
    cap_show.add_argument("source", choices=sorted(CAPABILITIES))
    cap_doctor = cap_sub.add_parser("doctor", help="Check adapters, licences and safety gates")
    cap_doctor.add_argument("--json", action="store_true")
    cap_ingest = cap_sub.add_parser(
        "ingest", help="Normalize and preserve an approved JSON/JSONL engine export"
    )
    cap_ingest.add_argument("--case", required=True)
    cap_ingest.add_argument("--source", required=True, choices=sorted(CAPABILITIES))
    cap_ingest.add_argument("--file", type=Path, required=True)
    cap_ingest.add_argument("--authorized", action="store_true")
    cap_ingest.add_argument("--subject-consent", action="store_true")
    cap_ingest.add_argument("--owned-org", action="store_true")
    cap_stage = cap_sub.add_parser("stage-file", help="Safely stage a local file for document/geospatial MCP tools")
    cap_stage.add_argument("--case", required=True)
    cap_stage.add_argument("--file", type=Path, required=True)
    cap_stage.add_argument("--authorized", action="store_true")
    cap_stage.add_argument("--owned-asset", action="store_true")
    cap_stage.add_argument("--owned-org", action="store_true")
    cap_mcp_tools = cap_sub.add_parser("mcp-tools", help="List policy-allowed tools from an installed MCP server")
    cap_mcp_tools.add_argument("--source", required=True, choices=sorted(
        key for key, value in CAPABILITIES.items() if value.protocol == "mcp"
    ))
    cap_mcp_tools.add_argument("--authorized", action="store_true")
    cap_mcp_tools.add_argument("--timeout", type=int, default=30)
    cap_mcp_call = cap_sub.add_parser("mcp-call", help="Call one allowlisted MCP tool and preserve its result")
    cap_mcp_call.add_argument("--case", required=True)
    cap_mcp_call.add_argument("--source", required=True, choices=sorted(
        key for key, value in CAPABILITIES.items() if value.protocol == "mcp"
    ))
    cap_mcp_call.add_argument("--tool", required=True)
    cap_mcp_call.add_argument("--arguments-file", type=Path, required=True)
    cap_mcp_call.add_argument("--authorized", action="store_true")
    cap_mcp_call.add_argument("--subject-consent", action="store_true")
    cap_mcp_call.add_argument("--owned-org", action="store_true")
    cap_mcp_call.add_argument("--timeout", type=int, default=30)
    cap_plan = cap_sub.add_parser("research-plan", help="Build an authority-bound investigation DAG")
    cap_plan.add_argument("--objective", required=True)
    cap_plan.add_argument("--scope-type", required=True, choices=["organisation", "domain", "topic", "person"])
    cap_plan.add_argument("--authority", required=True)
    cap_plan.add_argument("--subject-consent", action="store_true")
    cap_brief = cap_sub.add_parser("research-brief", help="Deduplicate evidence and separate facts from inferences")
    cap_brief.add_argument("--case", required=True)
    cap_brief.add_argument("--file", type=Path, required=True)
    cap_brief.add_argument("--authorized", action="store_true")
    cap_service = cap_sub.add_parser("service-call", help="Call a bounded Crawl4AI or Firecrawl worker")
    cap_service.add_argument("--case", required=True)
    cap_service.add_argument("--source", required=True, choices=["crawl4ai", "firecrawl", "searxng", "scrapegraph-ai"])
    cap_service.add_argument("--action", required=True, choices=["crawl", "search", "scrape", "map", "extract"])
    cap_service.add_argument("--target", required=True)
    cap_service.add_argument("--options-file", type=Path)
    cap_service.add_argument("--authorized", action="store_true")
    cap_service.add_argument("--owned-org", action="store_true")
    cap_service.add_argument("--timeout", type=int, default=60)
    cap_training_validate = cap_sub.add_parser("training-validate", help="Validate a FreeOSINT-style JSON module")
    cap_training_validate.add_argument("--file", type=Path, required=True)
    cap_training_record = cap_sub.add_parser("training-record", help="Record local lesson progress")
    cap_training_record.add_argument("--module", required=True)
    cap_training_record.add_argument("--lesson", required=True)
    cap_training_record.add_argument("--score", required=True, type=int)
    cap_sub.add_parser("training-progress", help="Show local training progress")

    cti = sub.add_parser("cti", help="Extract, correlate and exchange cyber threat intelligence")
    cti_sub = cti.add_subparsers(dest="cti_command", required=True)
    cti_extract = cti_sub.add_parser("extract", help="Extract IOCs, CVEs and ATT&CK references from a report")
    cti_extract.add_argument("--case", required=True)
    cti_extract.add_argument("--file", type=Path, required=True)
    cti_extract.add_argument("--mapping-file", type=Path)
    cti_extract.add_argument("--authorized", action="store_true")
    cti_feed = cti_sub.add_parser("feed-ingest", help="Normalize and CVE-deduplicate an approved JSON/RSS feed")
    cti_feed.add_argument("--case", required=True)
    cti_feed.add_argument("--file", type=Path, required=True)
    cti_feed.add_argument("--source", required=True)
    cti_feed.add_argument("--authorized", action="store_true")
    cti_trends = cti_sub.add_parser("trends", help="Summarize source and CVE counts from ingested records")
    cti_trends.add_argument("--case", required=True)
    cti_stix = cti_sub.add_parser("export-stix", help="Export an extracted graph as a STIX 2.1 bundle")
    cti_stix.add_argument("--case", required=True)
    cti_stix.add_argument("--graph", type=Path, required=True)
    cti_stix.add_argument("--output", type=Path, required=True)
    cti_stix.add_argument("--authorized", action="store_true")

    fusion = sub.add_parser("fusion", help="Rank multi-source evidence with explicit contradictions and uncertainty")
    fusion_sub = fusion.add_subparsers(dest="fusion_command", required=True)
    fusion_rank = fusion_sub.add_parser("rank", help="Build a deterministic evidence candidate board")
    fusion_rank.add_argument("--case", required=True)
    fusion_rank.add_argument("--file", type=Path, required=True)
    fusion_rank.add_argument("--scope", required=True, choices=sorted(SCOPES))
    fusion_rank.add_argument("--authorized", action="store_true")
    fusion_rank.add_argument("--subject-consent", action="store_true")
    fusion_rank.add_argument("--owned-asset", action="store_true")
    fusion_rank.add_argument("--owned-org", action="store_true")
    fusion_auto = fusion_sub.add_parser("auto-rank", help="Rank signals already stored in a case")
    fusion_auto.add_argument("--case", required=True)
    fusion_auto.add_argument("--scope", required=True, choices=sorted(SCOPES))
    fusion_auto.add_argument("--authorized", action="store_true")
    fusion_auto.add_argument("--subject-consent", action="store_true")
    fusion_auto.add_argument("--owned-asset", action="store_true")
    fusion_auto.add_argument("--owned-org", action="store_true")
    fusion_geo = fusion_sub.add_parser("geojson", help="Export coarse consented/owned location candidates")
    fusion_geo.add_argument("--case", required=True)
    fusion_geo.add_argument("--file", type=Path, required=True)
    fusion_geo.add_argument("--output", type=Path, required=True)
    fusion_geo.add_argument("--authorized", action="store_true")
    fusion_geo.add_argument("--subject-consent", action="store_true")
    fusion_geo.add_argument("--owned-asset", action="store_true")

    add_research_parser(sub)

    resolve = sub.add_parser(
        "resolve", help="Queue and adjudicate explainable public-entity match candidates"
    )
    resolve_sub = resolve.add_subparsers(dest="resolve_command", required=True)
    resolve_propose = resolve_sub.add_parser(
        "propose", help="Compare two public records and create a human-review candidate"
    )
    resolve_propose.add_argument("--case", required=True)
    resolve_propose.add_argument("--left", type=Path, required=True)
    resolve_propose.add_argument("--right", type=Path, required=True)
    resolve_propose.add_argument("--source", required=True)
    resolve_propose.add_argument("--authority", required=True)
    resolve_propose.add_argument("--authorized", action="store_true")
    resolve_queue = resolve_sub.add_parser("queue", help="List resolution candidates")
    resolve_queue.add_argument("--case", required=True)
    resolve_queue.add_argument(
        "--status", choices=["pending", "accepted", "rejected", "all"], default="pending"
    )
    resolve_decide = resolve_sub.add_parser(
        "decide", help="Record a human decision without automatic identity merging"
    )
    resolve_decide.add_argument("--candidate", required=True)
    resolve_decide.add_argument("--decision", choices=["accepted", "rejected"], required=True)
    resolve_decide.add_argument("--reviewer", required=True)
    resolve_decide.add_argument("--rationale", required=True)
    resolve_decide.add_argument("--authorized", action="store_true")

    casework = sub.add_parser("casework", help="Manage analyst notes and review context")
    casework_sub = casework.add_subparsers(dest="casework_command", required=True)
    note_add = casework_sub.add_parser("note-add", help="Add a privacy-reduced case note")
    note_add.add_argument("--case", required=True)
    note_add.add_argument("--author", required=True)
    note_add.add_argument("--classification", choices=["fact", "analysis", "question"], required=True)
    note_add.add_argument("--body", required=True)
    note_list = casework_sub.add_parser("notes", help="List case notes")
    note_list.add_argument("--case", required=True)

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
        if not key or key not in {"module", "wordlist", "resolvers", "sources"}:
            raise PolicyError(f"Unsupported tool option: {key or '<empty>'}")
        result[key] = value.strip()
    return result


def _json_object(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"Invalid JSON record: {path}") from exc
    if not isinstance(value, dict):
        raise PolicyError("Entity record files must contain one JSON object")
    return value


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
    if args.command == "research":
        try:
            return run_research(args)
        except (PolicyError, ValueError, KeyError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
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
        elif args.command == "search":
            if not engine.db.get_case(args.case):
                raise PolicyError(f"Unknown case: {args.case}")
            if not 1 <= args.limit <= 100:
                raise PolicyError("Search result limit must be between 1 and 100")
            if not args.query.strip() or len(args.query) > 500:
                raise PolicyError("Search query must contain 1-500 characters")
            results = bm25_search(
                engine.db.searchable_documents(args.case), args.query, limit=args.limit
            )
            print(json.dumps({"case_id": args.case, "query": args.query,
                              "results": results}, indent=2, ensure_ascii=False))
        elif args.command == "resolve":
            resolver = ResolutionService(engine.db)
            if args.resolve_command == "propose":
                result = resolver.propose(
                    args.case, _json_object(args.left), _json_object(args.right),
                    source=args.source, authority=args.authority, authorized=args.authorized,
                )
            elif args.resolve_command == "queue":
                result = {"case_id": args.case, "status": args.status,
                          "candidates": resolver.queue(args.case, status=args.status)}
            else:
                result = resolver.decide(
                    args.candidate, args.decision, reviewer=args.reviewer,
                    rationale=args.rationale, authorized=args.authorized,
                )
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif args.command == "casework":
            if not engine.db.get_case(args.case):
                raise PolicyError(f"Unknown case: {args.case}")
            if args.casework_command == "note-add":
                author, body = args.author.strip(), sanitize_text(args.body.strip(), 4000)
                if (not 2 <= len(author) <= 120 or any(ord(char) < 32 for char in author)
                        or not body):
                    raise PolicyError("Case note requires a valid author and non-empty body")
                row = {"id": str(uuid4()), "case_id": args.case, "author": author,
                       "classification": args.classification, "body": body,
                       "created_at": utc_now()}
                engine.db.add_case_note(row)
                result = row
            else:
                result = {"case_id": args.case, "notes": engine.db.case_notes(args.case)}
            print(json.dumps(result, indent=2, ensure_ascii=False))
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
        elif args.command == "readiness":
            result = ReadinessScorecard(engine.db, args.workspace).run(production=args.production)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Core ready: {result['core_ready']}")
                print(f"Production ready: {result['production_ready']}")
                print(f"Competitive ready: {result['competitive_ready']}")
                print(f"Verified score: {result['score']}/100")
                for row in result["gates"]:
                    print(f"{row['state'].upper():4} {row['name']}: {row['observed']}")
        elif args.command == "automation":
            manager = AutomationManager(engine)
            if args.automation_command == "add":
                result = manager.add(
                    args.case, args.name, args.method, args.target_type, args.target,
                    args.every_minutes, args.authority, authorized=args.authorized,
                )
                print(json.dumps(result, indent=2))
            elif args.automation_command == "list":
                rows = engine.db.automation_jobs(args.case)
                if args.json:
                    print(json.dumps(rows, indent=2))
                elif not rows:
                    print("No local schedules configured.")
                else:
                    for row in rows:
                        state = "ENABLED" if row["enabled"] else "DISABLED"
                        print(f"{row['id']} {state:8} {row['method_key']:24} "
                              f"next={row['next_run_at']} {row['name']}")
            elif args.automation_command == "run-due":
                print(json.dumps(manager.run_due(args.limit), indent=2))
            elif args.automation_command == "history":
                if not 1 <= args.limit <= 500:
                    raise PolicyError("History limit must be between 1 and 500")
                print(json.dumps(engine.db.automation_runs(args.schedule, args.limit), indent=2))
            elif args.automation_command == "alerts":
                if not 1 <= args.limit <= 500:
                    raise PolicyError("Alert limit must be between 1 and 500")
                print(json.dumps(engine.db.alerts(args.case, args.open_only, args.limit), indent=2))
            elif args.automation_command == "ack":
                if not engine.db.acknowledge_alert(args.alert):
                    raise PolicyError("Open alert not found")
                print(json.dumps({"alert": args.alert, "status": "acknowledged"}))
            elif args.automation_command in {"enable", "disable"}:
                enabled = args.automation_command == "enable"
                if not engine.db.set_automation_enabled(args.schedule, enabled):
                    raise PolicyError("Schedule not found")
                print(json.dumps({"schedule": args.schedule,
                                  "status": "enabled" if enabled else "disabled"}))
        elif args.command == "deployment":
            result = DeploymentDoctor().run(production=args.production)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                for row in result["checks"]:
                    print(f"{row['state'].upper():4} {row['name']:42} {row['detail']}")
                print("Summary: " + json.dumps(result["summary"], sort_keys=True))
            return 0 if result["ready"] else 2
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
                        print(f"{row['name']:15} {row['readiness'].upper():26} "
                              f"{row['verification'].upper():9} {row['description']}")
            elif args.integration_command == "show":
                row = next(item for item in runner.inventory() if item["name"] == args.tool)
                print(json.dumps(row, indent=2))
            elif args.integration_command == "doctor":
                rows = runner.inventory()
                summary = {
                    "supported": len(rows),
                    "executable_adapters": sum(row["executable"] for row in rows),
                    "installed": sum(row["installed"] and row["executable"] for row in rows),
                    "verified": sum(row["verification"] == "verified" for row in rows),
                    "degraded": [row["name"] for row in rows if row["verification"] in {"degraded", "failed"}],
                    "missing": [row["name"] for row in rows if row["executable"] and not row["installed"]],
                    "blocked": [row["name"] for row in rows if not row["executable"]],
                    "profiles": {name: list(tools) for name, tools in PROFILES.items()},
                }
                if args.json:
                    print(json.dumps(summary, indent=2))
                else:
                    print(f"Supported: {summary['supported']}")
                    print(f"Executable adapters: {summary['executable_adapters']}")
                    print(f"Installed: {summary['installed']}")
                    print(f"Execution verified: {summary['verified']}")
                    print("Degraded/failed: " + (", ".join(summary["degraded"]) or "none"))
                    print("Missing: " + (", ".join(summary["missing"]) or "none"))
                    print("Blocked by policy: " + ", ".join(summary["blocked"]))
            elif args.integration_command == "lock":
                print(json.dumps(IntegrationLock(runner).write(args.output), indent=2))
            elif args.integration_command == "verify-lock":
                result = IntegrationLock(runner).verify(args.file)
                print(json.dumps(result, indent=2))
                if not result["valid"]:
                    return 2
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
        elif args.command == "intel":
            hub = IntelligenceHub(engine.db, args.workspace)
            if args.intel_command == "sources":
                rows = hub.sources()
                if args.json:
                    print(json.dumps(rows, indent=2))
                else:
                    for row in rows:
                        live = "LIVE" if row["live_connector"] else "IMPORT"
                        print(f"{row['name']:20} {live:6} {row['category']:24} {row['description']}")
            elif args.intel_command == "doctor":
                rows = hub.sources()
                credentials = {
                    key: bool(__import__("os").environ.get(key))
                    for row in rows for key in row["credential_env"]
                }
                result = {
                    "sources": len(rows),
                    "live_connectors": sum(row["live_connector"] for row in rows),
                    "credentials": credentials,
                    "media_tools": MediaAnalyzer.capabilities(),
                    "local_ai": {"provider": "Ollama", "configured_on_request": True},
                }
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    print(f"Sources: {result['sources']}")
                    print(f"Live connectors: {result['live_connectors']}")
                    print("Credentials: " + json.dumps(credentials, sort_keys=True))
                    print("Media tools: " + json.dumps(result["media_tools"], sort_keys=True))
            elif args.intel_command == "health":
                rows = engine.db.connector_health()
                for row in rows:
                    row["warning"] = row["consecutive_failures"] >= 3
                if args.json:
                    print(json.dumps(rows, indent=2))
                elif not rows:
                    print("No live connector calls recorded in this workspace.")
                else:
                    for row in rows:
                        state = "WARN" if row["warning"] else "OK"
                        print(f"{row['source']:16} {state:4} failures={row['consecutive_failures']} "
                              f"last_success={row['last_success_at'] or 'never'}")
            elif args.intel_command in {"ingest", "collect"}:
                common = {
                    "authorized": args.authorized,
                    "subject_consent": args.subject_consent,
                    "owned_org": args.owned_org,
                    "owned_asset": args.owned_asset,
                    "public_record_basis": args.public_record_basis,
                }
                if args.intel_command == "ingest":
                    result = hub.ingest(args.case, args.source, args.file, **common)
                else:
                    result = hub.collect(
                        args.case, args.source, args.target_type, args.target, **common
                    )
                print(json.dumps(result, indent=2))
            elif args.intel_command == "media":
                result = MediaAnalyzer(engine.db, args.workspace).analyze(
                    args.case, args.file, authorized=args.authorized,
                    subject_consent=args.subject_consent, owned_asset=args.owned_asset,
                    ocr=args.ocr, transcribe=args.transcribe,
                    whisper_model=args.whisper_model, use_ollama=args.ollama,
                    ollama_model=args.model, ollama_url=args.ollama_url,
                )
                print(json.dumps(result, indent=2))
            elif args.intel_command == "analyze":
                if not args.authorized:
                    raise PolicyError("Intelligence analysis requires explicit --authorized confirmation")
                scan = engine.db.spider_scan(args.scan)
                if not scan or scan["case_id"] != args.case:
                    raise PolicyError("Scan does not belong to the specified case")
                analyzer = IntelligenceAnalyzer(engine.db)
                result = analyzer.analyze(
                    args.scan, use_ollama=args.ollama,
                    model=args.model, base_url=args.ollama_url,
                )
                if args.output:
                    analyzer.write(result, args.output)
                    result["output"] = str(args.output)
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
        elif args.command == "openosint":
            bridge = OpenOSINTBridge(engine.db, args.workspace)
            if args.openosint_command == "doctor":
                result = bridge.doctor()
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    for key, value in result.items():
                        print(f"{key}: {value}")
            elif args.openosint_command == "run":
                forwarded = list(args.arguments)
                if forwarded and forwarded[0] == "--":
                    forwarded = forwarded[1:]
                result = bridge.run(
                    args.case, forwarded, authorized=args.authorized,
                    subject_consent=args.subject_consent, owned_asset=args.owned_asset,
                    timeout=args.timeout,
                )
                print(json.dumps(result, indent=2))
        elif args.command == "capabilities":
            hub = CapabilityHub(engine.db, args.workspace)
            if args.capability_command == "list":
                rows = hub.inventory()
                if args.json:
                    print(json.dumps(rows, indent=2))
                else:
                    for row in rows:
                        state = "READY" if row["ready"] else "GATED"
                        print(f"{row['id']:22} {state:5} {row['integration']:11} {row['name']}")
            elif args.capability_command == "show":
                row = next(item for item in hub.inventory() if item["id"] == args.source)
                print(json.dumps(row, indent=2))
            elif args.capability_command == "doctor":
                result = hub.doctor()
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    print(f"Upstream engines: {result['upstream_engines']}")
                    print(f"Ready: {result['ready']}")
                    print("Restricted: " + (", ".join(result["restricted"]) or "none"))
            elif args.capability_command == "ingest":
                result = hub.ingest(
                    args.case, args.source, args.file, authorized=args.authorized,
                    subject_consent=args.subject_consent, owned_org=args.owned_org,
                )
                print(json.dumps(result, indent=2))
            elif args.capability_command == "stage-file":
                result = hub.stage_file(
                    args.case, args.file, authorized=args.authorized,
                    owned_asset=args.owned_asset, owned_org=args.owned_org,
                )
                print(json.dumps(result, indent=2))
            elif args.capability_command == "mcp-tools":
                result = hub.mcp_tools(
                    args.source, authorized=args.authorized, timeout=args.timeout
                )
                print(json.dumps(result, indent=2))
            elif args.capability_command == "mcp-call":
                try:
                    arguments = json.loads(args.arguments_file.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise PolicyError(f"Invalid MCP arguments file: {exc}") from exc
                if not isinstance(arguments, dict):
                    raise PolicyError("MCP arguments file must contain one JSON object")
                result = hub.mcp_call(
                    args.case, args.source, args.tool, arguments,
                    authorized=args.authorized, subject_consent=args.subject_consent,
                    owned_org=args.owned_org, timeout=args.timeout,
                )
                print(json.dumps(result, indent=2))
            elif args.capability_command == "research-plan":
                result = hub.research_plan(
                    args.objective, args.scope_type, args.authority,
                    subject_consent=args.subject_consent,
                )
                print(json.dumps(result, indent=2))
            elif args.capability_command == "research-brief":
                result = hub.research_brief(
                    args.case, args.file, authorized=args.authorized
                )
                print(json.dumps(result, indent=2))
            elif args.capability_command == "service-call":
                options = {}
                if args.options_file:
                    try:
                        options = json.loads(args.options_file.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError) as exc:
                        raise PolicyError(f"Invalid service options file: {exc}") from exc
                    if not isinstance(options, dict):
                        raise PolicyError("Service options file must contain one JSON object")
                result = hub.service_call(
                    args.case, args.source, args.action, args.target, options,
                    authorized=args.authorized, owned_org=args.owned_org, timeout=args.timeout,
                )
                print(json.dumps(result, indent=2))
            elif args.capability_command == "training-validate":
                print(json.dumps(TrainingStore.validate_module(args.file), indent=2))
            elif args.capability_command == "training-record":
                result = TrainingStore(args.workspace).record(args.module, args.lesson, args.score)
                print(json.dumps(result, indent=2))
            elif args.capability_command == "training-progress":
                print(json.dumps(TrainingStore(args.workspace).progress(), indent=2))
        elif args.command == "cti":
            cti_engine = CTIEngine(engine.db, args.workspace)
            if args.cti_command == "extract":
                result = cti_engine.extract(
                    args.case, args.file, authorized=args.authorized,
                    mapping_file=args.mapping_file,
                )
            elif args.cti_command == "feed-ingest":
                result = cti_engine.ingest_feed(
                    args.case, args.file, args.source, authorized=args.authorized,
                )
            elif args.cti_command == "trends":
                result = cti_engine.trends(args.case)
            elif args.cti_command == "export-stix":
                result = cti_engine.export_stix(
                    args.case, args.graph, args.output, authorized=args.authorized,
                )
            print(json.dumps(result, indent=2))
        elif args.command == "fusion":
            board = FusionBoard(engine.db, args.workspace)
            if args.fusion_command == "rank":
                result = board.rank(
                    args.case, args.file, args.scope, authorized=args.authorized,
                    subject_consent=args.subject_consent, owned_asset=args.owned_asset,
                    owned_org=args.owned_org,
                )
            elif args.fusion_command == "auto-rank":
                result = board.auto_rank(
                    args.case, args.scope, authorized=args.authorized,
                    subject_consent=args.subject_consent, owned_asset=args.owned_asset,
                    owned_org=args.owned_org,
                )
            elif args.fusion_command == "geojson":
                result = board.geojson(
                    args.case, args.file, args.output, authorized=args.authorized,
                    subject_consent=args.subject_consent, owned_asset=args.owned_asset,
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
