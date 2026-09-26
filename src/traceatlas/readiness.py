"""Honest, machine-readable product maturity gates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import __version__
from .capabilities import CapabilityHub
from .db import CaseDB
from .deployment import DeploymentDoctor
from .integrations import IntegrationRunner
from .intelligence import MediaAnalyzer, SOURCES
from .openosint_bridge import OpenOSINTBridge


class ReadinessScorecard:
    def __init__(self, db: CaseDB, workspace: Path, root: Path | None = None):
        self.db = db
        self.workspace = workspace
        self.root = (root or Path(__file__).resolve().parents[2]).resolve()

    def run(self, *, production: bool = False) -> dict[str, Any]:
        gates: list[dict[str, Any]] = []

        def gate(name: str, passed: bool, observed: Any, required: Any,
                 action: str, *, core: bool = False) -> None:
            gates.append({"name": name, "state": "pass" if passed else "fail",
                          "observed": observed, "required": required,
                          "core_gate": core, "recommended_action": None if passed else action})

        doctor = DeploymentDoctor(self.root)
        repository = doctor.run(production=False)
        deployment = doctor.run(production=production)
        gate("repository_integrity", repository["ready"], repository["summary"], "zero required failures",
             "Restore required deployment artifacts and version consistency.", core=True)

        marker = self.root / ".traceatlas/ready"
        marker_text = marker.read_text(encoding="utf-8", errors="replace") if marker.is_file() else ""
        marker_ok = f"version={__version__}" in marker_text and "verified_at=" in marker_text
        gate("regression_verification_marker", marker_ok, marker_ok, True,
             "Run TRACEATLAS_FORCE_SETUP=1 ./start.sh to compile and execute the full suite.", core=True)

        bridge = OpenOSINTBridge(self.db, self.workspace).doctor()
        bridge_ok = bool(bridge.get("runtime_ready"))
        gate("openosint_runtime", bridge_ok, bridge.get("runtime_ready"), True,
             "Run TRACEATLAS_RETRY_OPENOSINT=1 ./set.sh and inspect .traceatlas/setup.log.", core=True)

        tools = IntegrationRunner(self.db, self.workspace).inventory()
        installed = sum(row["installed"] and row["executable"] for row in tools)
        verified = sum(row["verification"] == "verified" for row in tools)
        gate("external_tool_pack", installed >= 10 and verified >= 5,
             {"installed": installed, "execution_verified": verified},
             {"installed": 10, "execution_verified": 5},
             "Install, pin and execute-contract-test the ten priority adapters; do not count registry entries as capability.")

        health = self.db.connector_health()
        provider_verified = sum(bool(row["last_success_at"]) and row["consecutive_failures"] == 0 for row in health)
        configured = sum(
            not spec.credential_env or all(__import__("os").environ.get(key) for key in spec.credential_env)
            for spec in SOURCES.values() if spec.live_connector
        )
        gate("live_provider_contracts", provider_verified >= 3,
             {"live_registered": sum(spec.live_connector for spec in SOURCES.values()),
              "credential_ready": configured, "execution_verified": provider_verified},
             {"execution_verified": 3},
             "Configure approved provider credentials and run mocked plus real sandbox contract checks.")

        media = MediaAnalyzer.capabilities()
        media_ready = sum(bool(value) for value in media.values())
        gate("local_media_pipeline", media_ready >= 3, media, "at least three local analyzers",
             "Install and verify ExifTool, FFprobe and Tesseract/Whisper in the private worker image.")

        upstream = CapabilityHub(self.db, self.workspace).doctor()
        gate("upstream_execution_boundaries", upstream.get("execution_verified", 0) >= 5,
             {"configured_ready": upstream.get("ready", 0),
              "execution_verified": upstream.get("execution_verified", 0),
              "engines": upstream.get("upstream_engines", 0)},
             {"execution_verified": 5},
             "Configure and execute-contract-test five high-value bounded upstream services.")

        try:
            self.db.resolution_candidates("__readiness_probe__")
            review_ready = True
        except Exception:
            review_ready = False
        gate("human_resolution_review", review_ready, review_ready, True,
             "Apply the local resolution schema and verify propose/decide lifecycle.", core=True)

        production_ok = bool(deployment.get("production_ready"))
        gate("production_control_plane", production_ok, deployment["summary"], "production_ready=true",
             "Configure Vercel/Supabase/private worker, then run hosted RLS, queue and recovery tests.")

        core_ready = all(row["state"] == "pass" for row in gates if row["core_gate"])
        competitive_ready = all(row["state"] == "pass" for row in gates)
        return {
            "version": __version__, "core_ready": core_ready,
            "production_ready": production_ok, "competitive_ready": competitive_ready,
            "score": round(100 * sum(row["state"] == "pass" for row in gates) / len(gates)),
            "gates": gates,
            "limitations": [
                "This scorecard verifies repository/runtime evidence, not vendor-scale data coverage.",
                "Commercial feeds, platform API access, SLAs and licensed datasets require contracts and operations, not code claims.",
            ],
        }
