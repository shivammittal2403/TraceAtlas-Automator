"""Transparent 10-point product maturity acceptance gates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .db import CaseDB
from .deployment import DeploymentDoctor
from .intelligence import MediaAnalyzer, SOURCES


class ProductMaturityScorecard:
    """Score repository/runtime evidence; never award points for marketing claims."""

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
            "evidence": evidence, "acceptance": acceptance,
        }

    def run(self, *, production: bool = False) -> dict[str, Any]:
        live_sources = {name for name, spec in SOURCES.items() if spec.live_connector}
        social_sources = {
            name for name, spec in SOURCES.items()
            if spec.live_connector and spec.category in {
                "social-media", "community-platform", "code-platform", "video-platform",
            }
        }
        health = self.db.connector_health()
        verified_sources = {
            row["source"] for row in health
            if row.get("last_success_at") and row.get("consecutive_failures") == 0
        }
        verified_social = verified_sources & social_sources
        integration_health = {
            row["tool"] for row in self.db.integration_health()
            if row.get("last_success_at") and row.get("consecutive_failures") == 0
        }
        media = MediaAnalyzer.capabilities()
        media_tools = sum(bool(value) for value in media.values())
        source_runs = self.db.source_runs(limit=5000)
        social_runs = sum(
            row["status"] == "completed" and row["source"] in social_sources
            for row in source_runs
        )
        deployment = DeploymentDoctor(self.root).run(production=production)
        production_ready = bool(deployment.get("production_ready"))

        dimensions: dict[str, list[dict[str, Any]]] = {
            "live_source_depth": [
                self._gate("fourteen_live_contracts", len(live_sources) >= 14, len(live_sources), ">=14"),
                self._gate("twenty_live_contracts", len(live_sources) >= 20, len(live_sources), ">=20"),
                self._gate("four_live_categories", len({SOURCES[x].category for x in live_sources}) >= 4,
                           len({SOURCES[x].category for x in live_sources}), ">=4"),
                self._gate("schema_contracts", self._contains("src/traceatlas/intelligence/provider.py", "provider_schema_mismatch"), True, "implemented"),
                self._gate("bounded_retries", self._contains("src/traceatlas/intelligence/provider.py", "max_attempts"), True, "implemented"),
                self._gate("circuit_breaker", self._contains("src/traceatlas/intelligence/orchestrator.py", "circuit_open"), True, "implemented"),
                self._gate("durable_source_runs", self._contains("src/traceatlas/db.py", "CREATE TABLE IF NOT EXISTS source_runs"), True, "implemented"),
                self._gate("three_live_executions", len(verified_sources) >= 3, len(verified_sources), ">=3 successful providers"),
                self._gate("ten_live_executions", len(verified_sources) >= 10, len(verified_sources), ">=10 successful providers"),
                self._gate("production_control_plane", production_ready, production_ready, "production_ready=true"),
            ],
            "social_intelligence": [
                self._gate("six_live_social_contracts", len(social_sources) >= 6, len(social_sources), ">=6"),
                self._gate("eight_live_social_contracts", len(social_sources) >= 8, len(social_sources), ">=8"),
                self._gate("normalized_profile_contract", (self.root / "src/traceatlas/intelligence/social.py").is_file(), True, "implemented"),
                self._gate("consent_gate", self._contains("src/traceatlas/intelligence/hub.py", "subject_consent or owned_org"), True, "implemented"),
                self._gate("exact_identifier_collection", self._contains("src/traceatlas/intelligence/hub.py", "one exact public user ID"), True, "implemented"),
                self._gate("human_resolution", self._contains("src/traceatlas/resolution.py", "automatic_merge"), True, "implemented"),
                self._gate("two_verified_social_sources", len(verified_social) >= 2, len(verified_social), ">=2"),
                self._gate("five_verified_social_sources", len(verified_social) >= 5, len(verified_social), ">=5"),
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
                self._gate("repeat_collection_evidence", sum(row["source"] == "misp" for row in source_runs) >= 2,
                           sum(row["source"] == "misp" for row in source_runs), ">=2 MISP runs"),
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
                self._gate("model_quality_benchmark", False, False, "versioned hallucination/citation benchmark"),
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
                self._gate("saved_graph_views", False, False, "persistent saved layouts and filters"),
                self._gate("realtime_collaboration", False, False, "conflict-safe multi-analyst collaboration"),
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
                self._gate("restore_drill", False, False, "dated successful backup restore drill"),
                self._gate("enterprise_federation", False, False, "SSO/SCIM lifecycle verified"),
            ],
        }
        rows = []
        for name, gates in dimensions.items():
            score = sum(gate["state"] == "pass" for gate in gates)
            rows.append({
                "area": name, "score": score, "maximum": 10, "gates": gates,
                "blocking_gates": [gate["name"] for gate in gates if gate["state"] == "fail"],
            })
        overall = round(sum(row["score"] for row in rows) / len(rows), 1)
        return {
            "overall": overall, "maximum": 10,
            "ten_of_ten": all(row["score"] == 10 for row in rows),
            "dimensions": rows,
            "evidence_context": {
                "live_contracts": len(live_sources), "verified_live_sources": len(verified_sources),
                "stored_source_runs": len(source_runs), "production_ready": production_ready,
            },
            "limitations": [
                "A repository score is not a claim of data coverage, accuracy, legality or investigative outcome.",
                "External provider access, licensed corpora, hosted isolation, restore drills, SSO/SCIM and model benchmarks need operational evidence.",
            ],
        }
