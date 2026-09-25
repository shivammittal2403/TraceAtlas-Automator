"""Dependency-free data and planning logic for the RedKross Vercel console.

The public API never receives a target. It returns argv templates that the
browser fills locally after validating the operator's input.
"""

from __future__ import annotations

from typing import Any


VERSION = "1.1.0"
TARGET_TYPES = ("domain", "ip", "url", "email", "username", "hash")
ENGINES = ("fusion", "traceatlas", "openosint")

CATALOG: dict[str, Any] = {
    "product": "RedKross TraceAtlas | OpenOSINT Fusion",
    "version": VERSION,
    "metrics": {
        "playbooks": 40,
        "external_adapters": 34,
        "openosint_tools": 20,
        "intelligence_sources": 16,
        "spider_modules": 9,
        "upstream_capability_engines": 40,
    },
    "engines": [
        {
            "id": "traceatlas",
            "name": "TraceAtlas",
            "role": "Governed cases, evidence, correlation and reporting",
        },
        {
            "id": "openosint",
            "name": "OpenOSINT 2.29",
            "role": "Preserved upstream CLI through an allowlisted bridge",
        },
        {
            "id": "fusion",
            "name": "Fusion",
            "role": "A single local workflow using both engines",
        },
    ],
    "deployment_boundary": {
        "executes_scans": False,
        "accepts_api_keys": False,
        "local_planner_stores_targets": False,
        "local_planner_processes_target_in_browser": True,
        "control_plane_stores_enrolled_owned_assets": True,
        "optional_control_plane": True,
        "worker_executes_allowlisted_jobs": True,
        "identity_targets_cloud_enabled": False,
    },
}


def _traceatlas_steps(target_type: str) -> list[dict[str, Any]]:
    common = [
        {
            "label": "Create an evidence case",
            "argv": [
                "./start.sh", "init", "{case_id}", "--title",
                "RedKross authorised review", "--purpose",
                "Authorised defensive OSINT review",
            ],
        }
    ]
    scans: dict[str, list[list[str]]] = {
        "domain": [
            ["./start.sh", "integrations", "pipeline", "--case", "{case_id}",
             "--domain", "{target}", "--authorized"],
            ["./start.sh", "spider", "scan", "--case", "{case_id}",
             "--seed-type", "domain", "--seed", "{target}", "--authorized"],
        ],
        "ip": [
            ["./start.sh", "spider", "scan", "--case", "{case_id}",
             "--seed-type", "ip", "--seed", "{target}", "--authorized"],
            ["./start.sh", "intel", "collect", "--case", "{case_id}",
             "--source", "shodan", "--target-type", "ip", "--target", "{target}",
             "--owned-asset", "--authorized"],
        ],
        "url": [[
            "./start.sh", "spider", "scan", "--case", "{case_id}",
            "--seed-type", "url", "--seed", "{target}", "--authorized",
        ]],
        "email": [[
            "./start.sh", "spider", "scan", "--case", "{case_id}",
            "--seed-type", "email", "--seed", "{target}", "--authorized",
        ]],
        "username": [[
            "./start.sh", "spider", "scan", "--case", "{case_id}",
            "--seed-type", "username", "--seed", "{target}", "--authorized",
        ]],
        "hash": [[
            "./start.sh", "intel", "collect", "--case", "{case_id}",
            "--source", "virustotal", "--target-type", "hash", "--target", "{target}",
            "--owned-asset", "--authorized",
        ]],
    }
    for index, argv in enumerate(scans[target_type], start=1):
        common.append({"label": f"TraceAtlas collection {index}", "argv": argv})
    common.append({
        "label": "Generate reviewable reports",
        "argv": ["./start.sh", "report", "--case", "{case_id}", "--output", "reports"],
    })
    return common


def _openosint_steps(target_type: str) -> list[dict[str, Any]]:
    command = {
        "domain": "dns",
        "ip": "abuseipdb",
        "url": "virustotal",
        "email": "email",
        "username": "username",
        "hash": "virustotal",
    }[target_type]
    attestation = "--subject-consent" if target_type in {"email", "username"} else "--owned-asset"
    return [{
        "label": "OpenOSINT compatibility collection",
        "argv": [
            "./start.sh", "openosint", "run", "--case", "{case_id}",
            "--authorized", attestation, "--", command, "{target}",
        ],
    }]


def build_plan(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("JSON body must be an object")
    if "target" in payload:
        raise ValueError("Do not send a target to this API; it is processed only in your browser")
    target_type = str(payload.get("target_type", "")).strip().lower()
    engine = str(payload.get("engine", "")).strip().lower()
    if target_type not in TARGET_TYPES:
        raise ValueError("Unsupported target type")
    if engine not in ENGINES:
        raise ValueError("Unsupported engine")
    if payload.get("authorized") is not True:
        raise ValueError("Explicit authorization confirmation is required")

    steps: list[dict[str, Any]] = []
    if engine in {"traceatlas", "fusion"}:
        steps.extend(_traceatlas_steps(target_type))
    elif engine == "openosint":
        steps.extend(_traceatlas_steps(target_type)[:1])
    if engine in {"openosint", "fusion"}:
        steps.extend(_openosint_steps(target_type))
    if engine == "openosint":
        steps.append({
            "label": "Generate reviewable reports",
            "argv": ["./start.sh", "report", "--case", "{case_id}", "--output", "reports"],
        })

    return {
        "version": VERSION,
        "engine": engine,
        "target_type": target_type,
        "target_received": False,
        "steps": steps,
        "notes": [
            "Run only against assets you own or subjects who consented.",
            "Commands run locally; this deployment performs no reconnaissance.",
            "Review evidence and provenance before drawing conclusions.",
        ],
    }
