"""Engineering checklist; enterprise maturity requires independent acceptance evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .db import CaseDB
from .deployment import DeploymentDoctor
from .intelligence import MediaAnalyzer, SOURCES
from .benchmark import GuardrailBenchmark
from .source_fabric.integration import IntegrationReceipts


class ProductMaturityScorecard:
    """Inventory local implementation checks without assigning an enterprise score."""

    def __init__(self, db: CaseDB, workspace: Path, root: Path | None = None):
        self.db = db
        self.workspace = workspace
        self.root = (root or Path(__file__).resolve().parents[2]).resolve()

    def _contains(self, relative: str, marker: str) -> bool:
        path = self.root / relative
        return path.is_file() and marker in path.read_text(encoding="utf-8", errors="replace")

    @staticmethod
    def _gate(name: str, passed: bool, evidence: Any, acceptance: str) -> dict[str, Any]:
        return {
            "name": name, "state": "pass" if passed else "fail",
            "evidence": False if evidence is True and not passed else evidence, "acceptance": acceptance,
        }

    def run(self, *, production: bool = False) -> dict[str, Any]:
        live_sources = {name for name, spec in SOURCES.items() if spec.live_connector}
        social_sources = {
            name for name, spec in SOURCES.items()
            if spec.live_connector and spec.category in {
                "social-media", "social-professional", "community-platform", "code-platform",
                "video-platform",
            }
        }
        health = self.db.connector_health()
        # A healthy row has no fixture/runtime/custody/code binding and is not proof.
        healthy_sources = {row["source"] for row in health
                           if row.get("last_success_at") and row.get("consecutive_failures") == 0}
        has_receipts = self.db.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='fabric_integration_receipts'"
        ).fetchone()
        receipts = IntegrationReceipts(self.db, self.workspace).verified() if has_receipts else []
        verified_sources = {row["source"] for row in receipts}
        verified_social = verified_sources & social_sources
        # Generic integration health does not distinguish fixture and real execution.
        integration_health = set()
        media = MediaAnalyzer.capabilities()
        media_tools = sum(bool(value) for value in media.values())
        source_runs = self.db.source_runs(limit=5000)
        social_runs = sum(
            row["status"] == "completed" and row["mode"] == "live" and row["source"] in verified_social
            for row in source_runs
        )
        deployment = DeploymentDoctor(self.root).run(production=production)
        production_ready = False  # Static deployment configuration cannot validate hosted operation.
        try:
            benchmark = GuardrailBenchmark().run()
            guardrail_benchmark = benchmark["status"] == "pass"
        except (OSError, ValueError):
            benchmark = {"status": "fail", "score": 0}
            guardrail_benchmark = False

        dimensions: dict[str, list[dict[str, Any]]] = {
            "live_source_depth": [
                self._gate("fourteen_coded_contracts", len(live_sources) >= 14, len(live_sources), ">=14"),
                self._gate("twenty_coded_contracts", len(live_sources) >= 20, len(live_sources), ">=20"),
                self._gate("four_coded_categories", len({SOURCES[x].category for x in live_sources}) >= 4,
                           len({SOURCES[x].category for x in live_sources}), ">=4"),
                self._gate("schema_contracts", self._contains("src/traceatlas/intelligence/provider.py", "provider_schema_mismatch"), True, "implemented"),
                self._gate("bounded_retries", self._contains("src/traceatlas/intelligence/provider.py", "max_attempts"), True, "implemented"),
                self._gate("circuit_breaker", self._contains("src/traceatlas/intelligence/orchestrator.py", "circuit_open"), True, "implemented"),
                self._gate("durable_source_runs", self._contains("src/traceatlas/db.py", "CREATE TABLE IF NOT EXISTS source_runs"), True, "implemented"),
                self._gate("three_revalidated_local_integrations", len(verified_sources) >= 3, len(verified_sources), ">=3 successful providers"),
                self._gate("ten_revalidated_local_integrations", len(verified_sources) >= 10, len(verified_sources), ">=10 successful providers"),
                self._gate("production_control_plane", production_ready, production_ready, "production_ready=true"),
            ],
            "social_intelligence": [
                self._gate("six_coded_social_contracts", len(social_sources) >= 6, len(social_sources), ">=6"),
                self._gate("eight_coded_social_contracts", len(social_sources) >= 8, len(social_sources), ">=8"),
                self._gate("normalized_profile_contract", (self.root / "src/traceatlas/intelligence/social.py").is_file(), True, "implemented"),
                self._gate("consent_gate", self._contains("src/traceatlas/intelligence/hub.py", "subject_consent or owned_org"), True, "implemented"),
                self._gate("exact_identifier_collection", self._contains("src/traceatlas/intelligence/hub.py", "one exact public user ID"), True, "implemented"),
                self._gate("human_resolution", self._contains("src/traceatlas/resolution.py", "automatic_merge"), True, "implemented"),
                self._gate("two_revalidated_social_integrations", len(verified_social) >= 2, len(verified_social), ">=2"),
                self._gate("five_revalidated_social_integrations", len(verified_social) >= 5, len(verified_social), ">=5"),
                self._gate("social_run_history", social_runs >= 1, social_runs, ">=1 completed stored run"),
                self._gate("production_social_operations", production_ready and len(verified_social) >= 5,
                           {"production": production_ready, "verified": len(verified_social)}, "production plus >=5 verified"),
            ],
            "dark_web_intelligence": [
                self._gate("clear_web_index", self._contains("src/traceatlas/sensitive/runner.py", "ahmia.fi"), True, "implemented"),
                self._gate("approved_feed_import", self._contains("src/traceatlas/sensitive/runner.py", "darkweb_feed"), True, "implemented"),
                self._gate("bounded_misp_service", self._contains("src/traceatlas/capabilities/service.py", "/attributes/restSearch"), True, "implemented"),
                self._gate("onion_fetch_disabled", self._contains("src/traceatlas/sensitive/runner.py", "onion_fetch_disabled"), True, "implemented"),
                self._gate("content_not_retained", self._contains("src/traceatlas/sensitive/runner.py", "content-not-retained"), True, "implemented"),
                self._gate("sensitive_audit", self._contains("src/traceatlas/db.py", "sensitive_audit"), True, "implemented"),
                self._gate("misp_execution_verified", "misp" in integration_health, "misp" in integration_health, "successful approved MISP call"),
                self._gate("repeat_collection_evidence", False,
                           "NOT_VERIFIED: generic run history does not prove approved live MISP execution", ">=2 MISP runs"),
                self._gate("licensed_corpus_operations", False, False, "licensed corpus plus documented authority/SLA"),
                self._gate("production_darkweb_operations", production_ready and "misp" in integration_health,
                           {"production": production_ready, "misp": "misp" in integration_health}, "production plus verified MISP"),
            ],
            "ai_media_intelligence": [
                self._gate("deterministic_baseline", self._contains("src/traceatlas/intelligence/ai.py", "deterministic_summary"), True, "implemented"),
                self._gate("strict_output_schema", self._contains("src/traceatlas/intelligence/ai.py", "unsupported fields"), True, "implemented"),
                self._gate("evidence_id_citations", self._contains("src/traceatlas/intelligence/ai.py", "cites unknown evidence"), True, "implemented"),
                self._gate("prompt_injection_labels", self._contains("src/traceatlas/intelligence/ai.py", "instruction_like_patterns"), True, "implemented"),
                self._gate("media_integrity_signals", self._contains("src/traceatlas/intelligence/media.py", "perceptual_hashes"), True, "implemented"),
                self._gate("three_media_analyzers", media_tools >= 3, media, ">=3 available locally"),
                self._gate("local_model_execution", "ollama" in verified_sources or "ollama" in integration_health,
                           "ollama" in verified_sources or "ollama" in integration_health, "successful model run"),
                self._gate("model_guardrail_benchmark", guardrail_benchmark,
                           {"status": benchmark.get("status"), "score": benchmark.get("score")},
                           "versioned schema/citation regression benchmark passes"),
                self._gate("deepfake_or_speaker_stack", False, False, "validated model stack with benchmark"),
                self._gate("production_model_monitoring", production_ready and "ollama" in integration_health,
                           production_ready, "production plus monitored model"),
            ],
            "investigation_ux": [
                self._gate("unified_workspace", (self.root / "src/traceatlas/investigation.py").is_file(), True, "implemented"),
                self._gate("evidence_graph", (self.root / "api/graph.py").is_file(), True, "implemented"),
                self._gate("case_timeline", self._contains("src/traceatlas/investigation.py", "timeline"), True, "implemented"),
                self._gate("case_notes", (self.root / "api/notes.py").is_file(), True, "implemented"),
                self._gate("review_queue", (self.root / "api/reviews.py").is_file(), True, "implemented"),
                self._gate("entity_resolution", (self.root / "src/traceatlas/resolution.py").is_file(), True, "implemented"),
                self._gate("source_slo_view", self._contains("src/traceatlas/investigation.py", "p95_duration_ms"), True, "implemented"),
                self._gate("saved_graph_views", self._contains(
                    "supabase/migrations/20260926000300_collaboration_views.sql", "create table public.case_views"
                ) and (self.root / "api/views.py").is_file(), True,
                           "persistent saved layouts and filters"),
                self._gate("realtime_collaboration", self._contains(
                    "supabase/migrations/20260926000300_collaboration_views.sql", "view revision conflict"
                ) and self._contains(
                    "supabase/migrations/20260926000300_collaboration_views.sql", "supabase_realtime"
                ) and (self.root / "api/collaboration.py").is_file(), True,
                           "RLS event stream plus optimistic concurrency"),
                self._gate("hosted_ux_verified", production_ready, production_ready, "production_ready=true"),
            ],
            "enterprise_readiness": [
                self._gate("tenant_rls", self._contains("supabase/migrations/20260925000100_traceatlas_control_plane.sql", "enable row level security"), True, "implemented"),
                self._gate("append_only_audit", self._contains("supabase/migrations/20260926000100_enterprise_controls.sql", "audit_events_append_only"), True, "implemented"),
                self._gate("retention_legal_hold", self._contains("supabase/migrations/20260926000100_enterprise_controls.sql", "legal_hold"), True, "implemented"),
                self._gate("aal2_privileged_actions", self._contains("supabase/migrations/20260926000200_identity_governance.sql", "aal2 required"), True, "implemented"),
                self._gate("secret_boundary", self._contains("vercel_control.py", "HttpOnly"), True, "implemented"),
                self._gate("supply_chain_evidence", (self.root / ".github/workflows/ci.yml").is_file() and (self.root / ".github/workflows/codeql.yml").is_file(), True, "CI and CodeQL"),
                self._gate("source_slo_history", bool(source_runs), len(source_runs), ">=1 stored run"),
                self._gate("hosted_tenant_tests", production_ready, production_ready, "hosted RLS/tenant suite passed"),
                self._gate("local_restore_drill", self._contains(
                    "src/traceatlas/operations.py", "PRAGMA integrity_check"
                ) and self._contains(
                    ".github/workflows/ci.yml", "operations restore-drill"
                ), True, "CI exercises local SQLite backup/restore; hosted recovery remains separate"),
                self._gate("enterprise_federation", False, False, "SSO/SCIM lifecycle verified"),
            ],
        }
        rows = []
        for name, gates in dimensions.items():
            score = sum(gate["state"] == "pass" for gate in gates)
            rows.append({
                "area": name, "passed_checks": score, "total_checks": len(gates), "gates": gates,
                "blocking_gates": [gate["name"] for gate in gates if gate["state"] == "fail"],
            })
        passed = sum(row["passed_checks"] for row in rows)
        total = sum(row["total_checks"] for row in rows)
        return {
            "schema": "traceatlas-engineering-checklist/v2",
            "assessment_kind": "engineering_checklist",
            "overall": None, "maximum": None, "ten_of_ten": False,
            "enterprise_assessment": {
                "state": "NOT_ESTABLISHED", "score": None, "target": 8,
                "accepted": False,
                "reason": "Local implementation checks do not establish enterprise acceptance.",
                "required_evidence": [
                    "Representative independently reviewed investigation and entity-resolution evaluations",
                    "Independent custody anchors and tamper/rollback verification",
                    "Qualified sources in the intended runtime with current operational evidence",
                    "Hosted tenant isolation, recovery, identity lifecycle and operational SLO verification",
                    "Authorized human acceptance of the defined enterprise gates",
                ],
            },
            "checklist": {"passed_checks": passed, "total_checks": total,
                          "completion_percent": round(100 * passed / total, 1)},
            "dimensions": rows,
            "evidence_context": {
                "coded_live_contracts": len(live_sources),
                "healthy_connector_rows": len(healthy_sources),
                "revalidated_local_integration_sources": len(verified_sources),
                "local_integration_sources": sorted(verified_sources),
                "stored_source_runs": len(source_runs),
                "production_configuration_ready": bool(deployment.get("production_configuration_ready")),
                "production_ready": False,
            },
            "limitations": [
                "Checklist completion counts implementation signals; it is not an enterprise score or field-accuracy measurement.",
                "File markers are static inventory, not executed tests. Available tools are not validated model performance.",
                "Revalidated integration receipts prove a bounded local lookup only, not source or production qualification.",
                "Connector and integration health alone cannot establish live execution or approved operation.",
                "Legacy overall/maximum are null; consumers must use checklist and enterprise_assessment separately.",
            ],
        }
