"""Canonical custody adapter for the uploaded intelligence suite."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys

from ..addons.intelligence_v1.registry import ROOT, catalog, contract
from ..policy import PolicyError
from .archive_actions import evidence_refs, fields

MAX_REPORT = 8 * 1024 * 1024


def execution_profile_sha256():
    """Version the reviewed code and contracts, independently of engine UUIDs."""
    paths = {"adapter": Path(__file__), "worker": ROOT / "worker.py",
             "registry": ROOT / "registry.py", "catalog": ROOT / "catalog.json"}
    identity = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in paths.items()}
    identity["python"] = list(sys.version_info[:3])
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def validate_case_input(value, case_id, depth=0):
    if depth > 20:
        raise PolicyError("Intelligence input nesting exceeds its limit")
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "case_id" and item != case_id:
                raise PolicyError("Intelligence records must belong to the current canonical case")
            if key in {"tenant_id", "workspace_id"}:
                raise PolicyError("Hosted tenant identifiers are not accepted by this local adapter")
            if key in {"permission", "authority", "authority_granted"}:
                raise PolicyError("Embedded permissions cannot grant intelligence authority")
            if key in {"sample", "use_sample", "demo"} and item is True:
                raise PolicyError("Embedded sample investigations cannot become case evidence")
            validate_case_input(item, case_id, depth + 1)
    elif isinstance(value, list):
        if len(value) > 500:
            raise PolicyError("Intelligence arrays require at most 500 items")
        for item in value:
            validate_case_input(item, case_id, depth + 1)


def run_offline(module_id, payload, *, timeout=20):
    item = contract(module_id)
    encoded = json.dumps({"module": module_id, "input": payload}, ensure_ascii=False, allow_nan=False).encode()
    if len(encoded) > 2 * 1024 * 1024:
        raise PolicyError("Intelligence input exceeds its limit")
    # Credentials and environment-dependent provider configuration are not inherited.
    env = {key: value for key, value in os.environ.items() if key in {"SYSTEMROOT", "WINDIR"}}
    command = [sys.executable, "-I", "-B", str(ROOT / "worker.py")]
    try:
        result = subprocess.run(command, input=encoded, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, cwd=ROOT, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise PolicyError("Offline intelligence exceeded its deadline; no evidence was added") from exc
    if result.returncode:
        category = result.stderr.decode("utf-8", errors="replace").split(":", 1)[0]
        category = category if category in {"ValueError", "TypeError", "PermissionError", "ImportError",
                                            "ModuleNotFoundError", "KeyError", "AttributeError"} else "RuntimeError"
        raise PolicyError(f"{module_id} rejected the supplied contract ({category}); no evidence was added")
    if len(result.stdout) > MAX_REPORT:
        raise PolicyError("Intelligence output exceeds the report limit")
    try:
        value = json.loads(result.stdout, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite output")))
    except (ValueError, UnicodeError) as exc:
        raise PolicyError("Intelligence output is not a finite JSON contract") from exc
    return item, value


def analyze(payload, evidence, input_id, case_id):
    fields(payload, {"module", "input", "evidence_ids"}, {"module", "input"})
    if not isinstance(payload["input"], dict):
        raise PolicyError("Intelligence input must be a module-specific object")
    validate_case_input(payload["input"], case_id)
    refs = evidence_refs(payload.get("evidence_ids", ["@input"]), evidence, input_id)
    item = contract(payload["module"])
    data = {**payload["input"], "case_id": case_id}
    # This consent is derived solely from ArchiveBridge's --authorized check.
    # It approves processing these bytes; it cannot approve provider collection.
    metadata = {"approved": True, "scope": "provided_records_only", "model_mode": "LOCAL_ONLY",
                "lawful_basis": "USER_APPROVED_LOCAL_SUBMISSION",
                "purpose": "Offline review of the submitted case records only",
                "context": "PROVIDED_RECORDS_ONLY_NO_EXTERNAL_COLLECTION"}
    if item.get("authorization_field_type"):
        data["authorization"] = ("USER_APPROVED_LOCAL_SUBMISSION_ONLY" if
                                 item["authorization_field_type"] == "str" else metadata)
    item, result = run_offline(payload["module"], data)
    return {"schema": "traceatlas.intelligence.review.v1", "module": item["id"],
            "module_version": item["version"], "module_sha256": item["file_sha256"],
            "execution_profile_sha256": execution_profile_sha256(),
            "execution_mode": item["mode"], "evidence_ids": refs,
            "draft": result, "semantic_class": "ANALYSIS_DRAFT", "requires_human_review": True,
            "network_calls": 0, "model_calls": 0, "authority_granted": False,
            "source_authenticity_verified": False, "factual_entailment_verified": False,
            "source_record_ids_are_canonical_evidence": False,
            "live_verified": False, "hosted_verified": False,
            "limitations": ["This review concerns the submitted records only.",
                            "Engine labels and confidence heuristics do not verify identity, truth or criminality.",
                            "A successful plan/scope check does not prove collection or source integration."]}
