#!/usr/bin/env python3
"""
TRACEATLAS PACKAGEINT — Safe Python Starter Implementation

Purpose:
  Evidence-first package ecosystem / software dependency intelligence pipeline.

Hard boundaries enforced in code:
  - Does NOT publish, upload, register, or create malicious/typosquat/backdoor packages.
  - Does NOT perform dependency-confusion exploitation or test hostile package resolution.
  - Does NOT poison dependencies, lockfiles, SBOMs, builds, or pipelines.
  - Does NOT use registry tokens, publisher credentials, or signing keys.
  - Does NOT take over maintainer/publisher accounts.
  - Does NOT execute, install, run, or import suspicious/untrusted packages.
  - Does NOT equate package name with package identity.
  - Does NOT equate manifest range with resolved version.
  - Does NOT equate resolved version with deployed version.
  - Does NOT equate SBOM with deployed reality.
  - Does NOT equate vulnerability presence with exploitation.
  - Does NOT equate malicious report with confirmed maliciousness without evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import unquote

VERSION = "0.1.0-packageint-safe-starter"
FAR_FUTURE = datetime(9999, 12, 31, tzinfo=timezone.utc)

# --------------------------------------------------------------------
# Policy / authorization constants
# --------------------------------------------------------------------

ALLOWED_SCOPES = {
    "public_and_authorized_records",
    "authorized_case_evidence",
    "authorized_package_registries",
    "authorized_software_inventory",
    "provided_records_only",
}

PROHIBITED_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?i)\b(publish|upload|register|create)\s+(a\s+)?(malicious|typosquat|backdoor|compromised|poisoned)\s+(package|version|release)\b"
        ),
        "MALICIOUS_PACKAGE_PUBLISHING",
    ),
    (
        re.compile(
            r"(?i)\b(exploit|attack|hijack|perform|test)\s+dependency[-_ ]confusion\b"
        ),
        "DEPENDENCY_CONFUSION_EXPLOITATION",
    ),
    (
        re.compile(
            r"(?i)\bdependency[-_ ]confusion\b.*\b(by\s+(publishing|registering|uploading)|maliciously|to\s+(hijack|exploit))\b"
        ),
        "DEPENDENCY_CONFUSION_EXPLOITATION",
    ),
    (
        re.compile(
            r"(?i)\b(poison|backdoor|inject)\s+(dependency|package|build|lockfile|sbom|pipeline)\b"
        ),
        "SUPPLY_CHAIN_POISONING",
    ),
    (
        re.compile(
            r"(?i)\b(steal|use|exfiltrate|leverate)\s+(registry token|publisher credential|signing key|package credential)\b"
        ),
        "CREDENTIAL_THEFT_OR_USE",
    ),
    (
        re.compile(
            r"(?i)\b(execute|run|install|import)\s+(a\s+)?(suspicious|malicious|untrusted|unknown)\s+package\b"
        ),
        "UNTRUSTED_PACKAGE_EXECUTION",
    ),
    (
        re.compile(
            r"(?i)\b(take over|hijack)\s+(maintainer|publisher|package) account\b"
        ),
        "ACCOUNT_TAKEOVER_REQUEST",
    ),
    (
        re.compile(
            r"(?i)\b(delete|yank|transfer)\s+(package|release)\b.*\b(without authorization|malicious|covert)\b"
        ),
        "UNAUTHORIZED_PACKAGE_LIFECYCLE_ACTION",
    ),
]

SOURCE_RELIABILITY: Dict[str, float] = {
    "official_registry": 0.90,
    "registry_api": 0.88,
    "signed_release": 0.88,
    "attested_build": 0.86,
    "official_repository": 0.84,
    "vendor_advisory": 0.84,
    "government_advisory": 0.82,
    "osv_like_feed": 0.74,
    "authorized_internal_inventory": 0.86,
    "sbom": 0.72,
    "lockfile": 0.78,
    "manifest": 0.70,
    "artifact_metadata": 0.76,
    "security_researcher": 0.58,
    "commercial_scanner": 0.55,
    "community_report": 0.42,
    "anonymous_post": 0.18,
    "unknown": 0.30,
}

HIGH_AUTHORITY_SOURCE_TYPES = {
    "official_registry",
    "registry_api",
    "signed_release",
    "attested_build",
    "official_repository",
    "vendor_advisory",
    "government_advisory",
    "authorized_internal_inventory",
}

PRIVATE_REGISTRY_TYPES = {"PRIVATE", "INTERNAL", "VENDOR"}

DEPENDENCY_TYPE_ALIASES = {
    "RUNTIME": "RUNTIME",
    "PROD": "RUNTIME",
    "PRODUCT": "RUNTIME",
    "DEPENDENCIES": "RUNTIME",
    "DEV": "DEVELOPMENT",
    "DEVELOPMENT": "DEVELOPMENT",
    "DEVDEPENDENCIES": "DEVELOPMENT",
    "TEST": "TEST",
    "BUILD": "BUILD",
    "OPTIONAL": "OPTIONAL",
    "PEER": "PEER",
    "PROVIDED": "PROVIDED",
    "SYSTEM": "SYSTEM",
    "BUNDLED": "BUNDLED",
    "VENDORED": "VENDORED",
    "PLUGIN": "PLUGIN",
}


# --------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(json_safe(p)) for p in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [json_safe(x) for x in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, timedelta):
        return obj.total_seconds()
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    return str(obj)


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    s = unicodedata.normalize("NFKC", str(value))
    s = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", s)
    return s.strip()


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if isinstance(dt, datetime) else None


def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def unique_preserve(items: Iterable[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        key = json_safe(item)
        if isinstance(key, (dict, list)):
            key = json.dumps(key, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def add_unique(lst: List[Any], item: Any) -> None:
    if item is None:
        return
    key = json_safe(item)
    if isinstance(key, (dict, list)):
        key = json.dumps(key, sort_keys=True, ensure_ascii=False)
    for existing in lst:
        ex_key = json_safe(existing)
        if isinstance(ex_key, (dict, list)):
            ex_key = json.dumps(ex_key, sort_keys=True, ensure_ascii=False)
        if ex_key == key:
            return
    lst.append(item)


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    s = normalize_text(value)
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%Y-%m",
        "%Y",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    return None


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def mask_value(value: Any, keep_prefix: int = 3, keep_suffix: int = 2) -> str:
    s = normalize_text(value)
    if not s:
        return ""
    if len(s) <= keep_prefix + keep_suffix:
        return "*" * len(s)
    return s[:keep_prefix] + "*" * (len(s) - keep_prefix - keep_suffix) + s[-keep_suffix:]


# --------------------------------------------------------------------
# Policy / authorization
# --------------------------------------------------------------------

def collect_intent_text(manifest: Dict[str, Any]) -> str:
    parts = [
        normalize_text(manifest.get("objective", "")),
        " ".join(normalize_text(q) for q in manifest.get("questions", []) or []),
        " ".join(normalize_text(x) for x in manifest.get("requested_actions", []) or []),
    ]
    return " ".join(parts)


def policy_screen(manifest: Dict[str, Any]) -> List[str]:
    blob = collect_intent_text(manifest)
    blocked = []
    for pat, label in PROHIBITED_PATTERNS:
        if pat.search(blob):
            blocked.append(label)
    return list(dict.fromkeys(blocked))


def has_private_registry_context(manifest: Dict[str, Any]) -> bool:
    for r in manifest.get("registries", []) or []:
        if normalize_text(r.get("registry_type", "")).upper() in PRIVATE_REGISTRY_TYPES:
            return True
    for p in manifest.get("packages", []) or []:
        if normalize_text(p.get("registry_type", "")).upper() in PRIVATE_REGISTRY_TYPES:
            return True
    for ip in manifest.get("internal_packages", []) or []:
        if normalize_text(ip.get("registry_type", "INTERNAL")).upper() in PRIVATE_REGISTRY_TYPES:
            return True
    return False


def authorization_check(manifest: Dict[str, Any]) -> Tuple[bool, List[str]]:
    auth = manifest.get("authorization") or {}
    reasons: List[str] = []

    if not auth.get("approved"):
        reasons.append("AUTHORIZATION_MISSING_OR_NOT_APPROVED")

    scope = auth.get("scope", "provided_records_only")
    if scope not in ALLOWED_SCOPES:
        reasons.append("UNSUPPORTED_SCOPE")

    model_mode = auth.get("model_mode", "LOCAL_ONLY")
    if model_mode == "CLOUD" and not auth.get("cloud_approved"):
        reasons.append("CLOUD_PROCESSING_NOT_APPROVED")

    if model_mode not in {"LOCAL_ONLY", "HYBRID", "CLOUD"}:
        reasons.append("UNKNOWN_MODEL_MODE")

    if has_private_registry_context(manifest) and not auth.get("private_registry_approved"):
        reasons.append("PRIVATE_REGISTRY_ACCESS_NOT_APPROVED")

    return (len(reasons) == 0), reasons


# --------------------------------------------------------------------
# Sources / pedigree / independence
# --------------------------------------------------------------------

def ingest_sources(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    sources: Dict[str, Dict[str, Any]] = {}
    for s in manifest.get("sources", []) or []:
        sid = normalize_text(s.get("source_id"))
        if not sid:
            continue
        stype = normalize_text(s.get("source_type", "unknown")).lower()
        reliability = s.get("reliability")
        if reliability is None:
            reliability = SOURCE_RELIABILITY.get(stype, SOURCE_RELIABILITY["unknown"])
        sources[sid] = {
            "source_id": sid,
            "source_type": stype,
            "upstream_source_id": normalize_text(s.get("upstream_source_id")) or None,
            "reliability": clamp(float(reliability)),
            "observed_at": normalize_text(s.get("observed_at")) or None,
            "url": s.get("url"),
            "limitations": list(s.get("limitations", []) or []),
        }
    return sources


def resolve_source_root(sid: str, sources: Dict[str, Dict[str, Any]], memo: Dict[str, str], visiting: Set[str]) -> str:
    if sid in memo:
        return memo[sid]
    if sid in visiting:
        return sid
    visiting.add(sid)
    src = sources.get(sid)
    if not src or not src.get("upstream_source_id"):
        memo[sid] = sid
        visiting.discard(sid)
        return sid
    root = resolve_source_root(src["upstream_source_id"], sources, memo, visiting)
    memo[sid] = root
    visiting.discard(sid)
    return root


def build_source_roots(sources: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    memo: Dict[str, str] = {}
    for sid in sources:
        resolve_source_root(sid, sources, memo, set())
    return memo


def source_family_ids(source_ids: List[str], source_roots: Dict[str, str]) -> List[str]:
    roots = []
    for sid in source_ids:
        roots.append(source_roots.get(sid, sid))
    return list(dict.fromkeys(roots))


def source_quality(source_ids: List[str], sources: Dict[str, Dict[str, Any]]) -> Tuple[float, float]:
    vals = [float(sources.get(sid, {}).get("reliability", SOURCE_RELIABILITY["unknown"])) for sid in source_ids]
    if not vals:
        return SOURCE_RELIABILITY["unknown"], SOURCE_RELIABILITY["unknown"]
    return max(vals), sum(vals) / len(vals)


def independence_state(families: List[str], sources: Dict[str, Dict[str, Any]], source_ids: List[str]) -> str:
    if not source_ids:
        return "UNKNOWN"
    if len(families) <= 1:
        return "DEPENDENT"
    types = {sources.get(sid, {}).get("source_type", "unknown") for sid in source_ids}
    rels = [sources.get(sid, {}).get("reliability", 0.3) for sid in source_ids]
    if len(types) == 1 and max(rels) < 0.70:
        return "PARTIALLY_DEPENDENT"
    if max(rels) >= 0.70:
        return "INDEPENDENT"
    return "PARTIALLY_DEPENDENT"


# --------------------------------------------------------------------
# Package identity / PURL / refs
# --------------------------------------------------------------------

def normalize_package_name(ecosystem: str, raw: str) -> str:
    eco = normalize_text(ecosystem).lower()
    s = normalize_text(raw)
    if not s:
        return ""
    if eco == "pypi":
        s = re.sub(r"[-_.]+", "-", s).lower()
    elif eco in {"npm", "cargo", "rubygems", "nuget", "hex", "packagist", "composer", "swift", "cocoapods", "maven", "go", "generic", "unknown"}:
        s = s.lower()
    else:
        s = s.lower()
    return s


def make_purl(ecosystem: str, namespace: Optional[str], name: str, version: Optional[str] = None) -> str:
    eco = normalize_text(ecosystem).lower() or "generic"
    nm = normalize_text(name)
    ns = normalize_text(namespace)
    parts = [f"pkg:{eco}"]
    if ns:
        parts.append(ns)
    if nm:
        parts.append(nm)
    p = "/".join(parts)
    if version:
        p += f"@{normalize_text(version)}"
    return p


def parse_purl(purl: str) -> Dict[str, Any]:
    s = normalize_text(purl)
    m = re.match(r"^pkg:([^/]+)/(.+?)(?:@([^#]+))?(?:\?.*)?(?:#.*)?$", s)
    if not m:
        return {
            "ecosystem": "unknown",
            "registry": "unknown",
            "namespace": None,
            "name": s or "UNKNOWN",
            "version": None,
            "repository_reference": None,
            "license": None,
        }
    eco = normalize_text(m.group(1)).lower()
    rem = unquote(m.group(2))
    ver = unquote(m.group(3)) if m.group(3) else None
    parts = [p for p in rem.split("/") if p]
    if len(parts) >= 2:
        ns = "/".join(parts[:-1])
        name = parts[-1]
    elif parts:
        ns = None
        name = parts[0]
    else:
        ns = None
        name = "UNKNOWN"
    return {
        "ecosystem": eco,
        "registry": "unknown",
        "namespace": ns or None,
        "name": name,
        "version": ver or None,
        "repository_reference": None,
        "license": None,
    }


def normalize_ref(ref: Any, default_ecosystem: str = "unknown", default_registry: str = "unknown") -> Dict[str, Any]:
    if isinstance(ref, dict):
        name = normalize_text(ref.get("name") or ref.get("package_name") or ref.get("artifact") or ref.get("id"))
        namespace = normalize_text(ref.get("namespace") or ref.get("scope") or ref.get("group")) or None
        if name.startswith("@") and "/" in name and not namespace:
            namespace, name = name.split("/", 1)
        return {
            "ecosystem": normalize_text(ref.get("ecosystem") or default_ecosystem).lower() or "unknown",
            "registry": normalize_text(ref.get("registry") or ref.get("registry_id") or default_registry).lower() or "unknown",
            "namespace": namespace or None,
            "name": name or "UNKNOWN",
            "version": normalize_text(ref.get("version")) or None,
            "repository_reference": normalize_text(ref.get("repository") or ref.get("repository_url") or ref.get("repo")) or None,
            "license": normalize_text(ref.get("license") or ref.get("spdx_license")) or None,
        }

    s = normalize_text(ref)
    if not s:
        return {
            "ecosystem": normalize_text(default_ecosystem).lower() or "unknown",
            "registry": normalize_text(default_registry).lower() or "unknown",
            "namespace": None,
            "name": "UNKNOWN",
            "version": None,
            "repository_reference": None,
            "license": None,
        }

    if s.startswith("pkg:"):
        parsed = parse_purl(s)
        parsed["ecosystem"] = parsed.get("ecosystem") or normalize_text(default_ecosystem).lower() or "unknown"
        parsed["registry"] = parsed.get("registry") or normalize_text(default_registry).lower() or "unknown"
        return parsed

    if ":" in s:
        eco, rest = s.split(":", 1)
        namespace = None
        name = rest
        if name.startswith("@") and "/" in name:
            namespace, name = name.split("/", 1)
        return {
            "ecosystem": normalize_text(eco).lower() or "unknown",
            "registry": normalize_text(default_registry).lower() or "unknown",
            "namespace": namespace,
            "name": name or "UNKNOWN",
            "version": None,
            "repository_reference": None,
            "license": None,
        }

    namespace = None
    name = s
    if name.startswith("@") and "/" in name:
        namespace, name = name.split("/", 1)
    return {
        "ecosystem": normalize_text(default_ecosystem).lower() or "unknown",
        "registry": normalize_text(default_registry).lower() or "unknown",
        "namespace": namespace,
        "name": name or "UNKNOWN",
        "version": None,
        "repository_reference": None,
        "license": None,
    }


# --------------------------------------------------------------------
# Core object builders
# --------------------------------------------------------------------

def ensure_version(
    versions: Dict[str, Dict[str, Any]],
    package_id: str,
    version: Any,
    release_time: Optional[datetime] = None,
    yanked: bool = False,
    yanked_at: Optional[datetime] = None,
    deprecated: bool = False,
    deprecated_at: Optional[datetime] = None,
    repository_revision: Optional[str] = None,
    signature_state: Optional[str] = None,
    attestation_state: Optional[str] = None,
    provenance: Optional[Any] = None,
    source_ids: Optional[List[str]] = None,
    confidence: float = 0.6,
) -> Optional[str]:
    v = normalize_text(version)
    if not v:
        return None
    vid = stable_id("PKGV", package_id, v)
    if vid not in versions:
        versions[vid] = {
            "package_version_id": vid,
            "package_id": package_id,
            "version": v,
            "normalized_version": v,
            "release_time": release_time,
            "yanked": bool(yanked),
            "yanked_at": yanked_at,
            "deprecated": bool(deprecated),
            "deprecated_at": deprecated_at,
            "artifact_ids": [],
            "repository_revision": normalize_text(repository_revision) or None,
            "signature_state": normalize_text(signature_state).upper() or "UNKNOWN",
            "attestation_state": normalize_text(attestation_state).upper() or "UNKNOWN",
            "provenance": provenance,
            "vulnerability_context": [],
            "malicious_context": [],
            "vex_records": [],
            "deployed_environments": [],
            "deployed_times": [],
            "licenses_observed": [],
            "source_ids": [],
            "evidence_ids": [],
            "confidence_score": clamp(float(confidence)),
            "limitations": [
                "Version metadata is registry/evidence-bound and may not represent deployed reality.",
                "Signature/attestation/provenance states are not security verdicts.",
            ],
        }
    ver = versions[vid]
    if release_time:
        ver["release_time"] = ver["release_time"] or release_time
    if yanked:
        ver["yanked"] = True
        ver["yanked_at"] = ver["yanked_at"] or yanked_at
    if deprecated:
        ver["deprecated"] = True
        ver["deprecated_at"] = ver["deprecated_at"] or deprecated_at
    if repository_revision:
        ver["repository_revision"] = normalize_text(repository_revision) or ver["repository_revision"]
    if signature_state:
        ver["signature_state"] = normalize_text(signature_state).upper() or ver["signature_state"]
    if attestation_state:
        ver["attestation_state"] = normalize_text(attestation_state).upper() or ver["attestation_state"]
    if provenance is not None:
        ver["provenance"] = provenance
    for sid in source_ids or []:
        add_unique(ver["source_ids"], normalize_text(sid))
    ver["confidence_score"] = max(float(ver["confidence_score"]), clamp(float(confidence)))
    return vid


def ensure_artifact(
    artifacts: Dict[str, Dict[str, Any]],
    version_id: Optional[str],
    artifact_id: Optional[str] = None,
    filename: Optional[str] = None,
    artifact_type: Optional[str] = None,
    size: Optional[int] = None,
    hashes: Optional[Dict[str, str]] = None,
    platform: Optional[str] = None,
    architecture: Optional[str] = None,
    signature: Optional[str] = None,
    source_ids: Optional[List[str]] = None,
) -> Optional[str]:
    if not version_id:
        return None
    hashes = hashes or {}
    aid = normalize_text(artifact_id) or stable_id("ART", version_id, filename or "", json_safe(hashes))
    if aid not in artifacts:
        artifacts[aid] = {
            "artifact_id": aid,
            "package_version_id": version_id,
            "filename": normalize_text(filename) or None,
            "artifact_type": normalize_text(artifact_type).upper() or "UNKNOWN",
            "size_bytes": int(size) if size is not None else None,
            "hashes": {},
            "platform": normalize_text(platform) or None,
            "architecture": normalize_text(architecture) or None,
            "signature": normalize_text(signature) or None,
            "source_ids": [],
            "limitations": [
                "Hash proves byte identity/integrity relative to a reference, not benignness.",
                "Artifact was not downloaded or executed by PACKAGEINT.",
            ],
        }
    art = artifacts[aid]
    for k, v in hashes.items():
        art["hashes"][normalize_text(k).lower()] = normalize_text(v)
    if filename:
        art["filename"] = art["filename"] or normalize_text(filename)
    if artifact_type:
        art["artifact_type"] = normalize_text(artifact_type).upper() or art["artifact_type"]
    if size is not None:
        art["size_bytes"] = int(size)
    if platform:
        art["platform"] = art["platform"] or normalize_text(platform)
    if architecture:
        art["architecture"] = art["architecture"] or normalize_text(architecture)
    if signature:
        art["signature"] = art["signature"] or normalize_text(signature)
    for sid in source_ids or []:
        add_unique(art["source_ids"], normalize_text(sid))
    return aid


def ensure_package(
    packages: Dict[str, Dict[str, Any]],
    ecosystem: Any,
    registry: Any,
    namespace: Any,
    name: Any,
    version: Any = None,
    source_ids: Optional[List[str]] = None,
    repository_reference: Optional[str] = None,
    license_metadata: Optional[str] = None,
    status: Optional[str] = None,
    confidence: float = 0.6,
    reason: str = "",
) -> str:
    eco = normalize_text(ecosystem).lower() or "unknown"
    reg = normalize_text(registry).lower() or "unknown"
    ns = normalize_text(namespace) or None
    raw = normalize_text(name) or "UNKNOWN"
    if raw.startswith("@") and "/" in raw and not ns:
        ns, raw = raw.split("/", 1)
    norm = normalize_package_name(eco, raw)
    pid = stable_id("PKG", eco, reg, ns or "", norm)

    if pid not in packages:
        packages[pid] = {
            "package_id": pid,
            "ecosystem": eco,
            "registry": reg,
            "namespace": ns,
            "name": raw,
            "normalized_name": norm,
            "purl": make_purl(eco, ns, raw),
            "repository_references": [],
            "publisher_candidates": [],
            "maintainer_candidates": [],
            "license_metadata": normalize_text(license_metadata) or None,
            "licenses_observed": [],
            "first_seen": None,
            "last_seen": None,
            "current_status": normalize_text(status).upper() or "UNKNOWN",
            "registry_type": None,
            "resolver_precedence": None,
            "source_ids": [],
            "evidence_ids": [],
            "confidence_score": clamp(float(confidence)),
            "malicious_context": [],
            "typosquat_context": [],
            "dependency_confusion_context": [],
            "limitations": [
                "Package identity is ecosystem/registry/namespace-bound; name alone is not global identity.",
                "Package is not repository, project, artifact, publisher, maintainer, or deployed runtime.",
            ] + ([f"Placeholder/reference created because: {reason}."] if reason else []),
        }

    pkg = packages[pid]
    for sid in source_ids or []:
        add_unique(pkg["source_ids"], normalize_text(sid))
    if repository_reference:
        add_unique(pkg["repository_references"], normalize_text(repository_reference))
    if license_metadata:
        pkg["license_metadata"] = pkg["license_metadata"] or normalize_text(license_metadata)
    if status:
        pkg["current_status"] = normalize_text(status).upper() or pkg["current_status"]
    pkg["confidence_score"] = max(float(pkg["confidence_score"]), clamp(float(confidence)))
    if version:
        ensure_version({}, pid, version, source_ids=source_ids, confidence=confidence)  # temporary no-op guard
        # Actual version is ensured by caller when versions dict is available.
    return pid


def ensure_ref_package(
    ref: Any,
    default_ecosystem: str,
    default_registry: str,
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
    source_ids: Optional[List[str]] = None,
    repository_reference: Optional[str] = None,
    license_metadata: Optional[str] = None,
    version_override: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    data = normalize_ref(ref, default_ecosystem, default_registry)
    pid = ensure_package(
        packages,
        data["ecosystem"],
        data["registry"],
        data["namespace"],
        data["name"],
        source_ids=source_ids,
        repository_reference=data.get("repository_reference") or repository_reference,
        license_metadata=data.get("license") or license_metadata,
        confidence=0.65,
        reason="package reference",
    )
    ver = version_override or data.get("version")
    vid = None
    if ver:
        vid = ensure_version(versions, pid, ver, source_ids=source_ids, confidence=0.65)
    return pid, vid


# --------------------------------------------------------------------
# Registries / packages / people / repositories
# --------------------------------------------------------------------

def ingest_registries(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    regs: Dict[str, Dict[str, Any]] = {}
    for r in manifest.get("registries", []) or []:
        rid = normalize_text(r.get("registry_id") or r.get("id") or r.get("name"))
        if not rid:
            continue
        rid = rid.lower()
        regs[rid] = {
            "registry_id": rid,
            "ecosystem": normalize_text(r.get("ecosystem", "unknown")).lower(),
            "registry_type": normalize_text(r.get("registry_type", "UNKNOWN")).upper(),
            "base_identity": normalize_text(r.get("base_identity") or r.get("url")) or None,
            "namespace_rules": normalize_text(r.get("namespace_rules")) or None,
            "version_rules": normalize_text(r.get("version_rules")) or None,
            "source_ids": [normalize_text(x) for x in r.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": list(r.get("limitations", []) or []) + [
                "Private/internal registry details must remain within authorization scope.",
            ],
        }
    return regs


def ingest_packages(
    manifest: Dict[str, Any],
    registries: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    packages: Dict[str, Dict[str, Any]] = {}
    versions: Dict[str, Dict[str, Any]] = {}
    artifacts: Dict[str, Dict[str, Any]] = {}

    for p in manifest.get("packages", []) or []:
        eco = p.get("ecosystem", "unknown")
        reg = p.get("registry") or p.get("registry_id") or "unknown"
        pid = ensure_package(
            packages,
            eco,
            reg,
            p.get("namespace") or p.get("scope") or p.get("group"),
            p.get("name") or p.get("package_name"),
            source_ids=p.get("source_ids"),
            repository_reference=p.get("repository") or p.get("repository_url"),
            license_metadata=p.get("license"),
            status=p.get("status"),
            confidence=p.get("confidence", 0.72),
            reason="explicit package record",
        )
        pkg = packages[pid]
        if normalize_text(p.get("registry_type")):
            pkg["registry_type"] = normalize_text(p.get("registry_type")).upper()
        if normalize_text(p.get("resolver_precedence")):
            pkg["resolver_precedence"] = normalize_text(p.get("resolver_precedence"))

        if p.get("version"):
            vid = ensure_version(
                versions,
                pid,
                p.get("version"),
                release_time=parse_time(p.get("release_time") or p.get("published_at")),
                yanked=bool(p.get("yanked")),
                yanked_at=parse_time(p.get("yanked_at")),
                deprecated=bool(p.get("deprecated")),
                deprecated_at=parse_time(p.get("deprecated_at")),
                repository_revision=p.get("repository_revision"),
                signature_state=p.get("signature_state"),
                attestation_state=p.get("attestation_state"),
                provenance=p.get("provenance"),
                source_ids=p.get("source_ids"),
                confidence=p.get("confidence", 0.72),
            )
            for a in p.get("artifacts", []) or []:
                aid = ensure_artifact(
                    artifacts,
                    vid,
                    artifact_id=a.get("artifact_id"),
                    filename=a.get("filename") or a.get("name"),
                    artifact_type=a.get("artifact_type") or a.get("kind"),
                    size=a.get("size"),
                    hashes=a.get("hashes"),
                    platform=a.get("platform"),
                    architecture=a.get("architecture"),
                    signature=a.get("signature"),
                    source_ids=a.get("source_ids") or p.get("source_ids"),
                )
                if vid and aid:
                    add_unique(versions[vid]["artifact_ids"], aid)

        for v in p.get("versions", []) or []:
            vid = ensure_version(
                versions,
                pid,
                v.get("version"),
                release_time=parse_time(v.get("release_time") or v.get("published_at")),
                yanked=bool(v.get("yanked")),
                yanked_at=parse_time(v.get("yanked_at")),
                deprecated=bool(v.get("deprecated")),
                deprecated_at=parse_time(v.get("deprecated_at")),
                repository_revision=v.get("repository_revision"),
                signature_state=v.get("signature_state"),
                attestation_state=v.get("attestation_state"),
                provenance=v.get("provenance"),
                source_ids=v.get("source_ids") or p.get("source_ids"),
                confidence=v.get("confidence", p.get("confidence", 0.72)),
            )
            for a in v.get("artifacts", []) or []:
                aid = ensure_artifact(
                    artifacts,
                    vid,
                    artifact_id=a.get("artifact_id"),
                    filename=a.get("filename") or a.get("name"),
                    artifact_type=a.get("artifact_type") or a.get("kind"),
                    size=a.get("size"),
                    hashes=a.get("hashes"),
                    platform=a.get("platform"),
                    architecture=a.get("architecture"),
                    signature=a.get("signature"),
                    source_ids=a.get("source_ids") or v.get("source_ids") or p.get("source_ids"),
                )
                if vid and aid:
                    add_unique(versions[vid]["artifact_ids"], aid)

    return packages, versions, artifacts


def ingest_repositories(manifest: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    repos: Dict[str, Dict[str, Any]] = {}
    for r in manifest.get("repositories", []) or []:
        rid = normalize_text(r.get("repository_id") or r.get("url") or r.get("canonical_url"))
        if not rid:
            continue
        repos[rid] = {
            "repository_id": rid,
            "url": normalize_text(r.get("url") or r.get("canonical_url")) or rid,
            "provider": normalize_text(r.get("provider") or r.get("platform")) or "unknown",
            "source_ids": [normalize_text(x) for x in r.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": ["Repository is not package; repository link may be stale."],
        }
    return repos


def ingest_people(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    publishers: List[Dict[str, Any]] = []
    maintainers: List[Dict[str, Any]] = []
    transfers: List[Dict[str, Any]] = []

    for pub in manifest.get("publishers", []) or []:
        pid, vid = ensure_ref_package(
            pub.get("package") or pub.get("package_ref"),
            pub.get("ecosystem", "unknown"),
            pub.get("registry", "unknown"),
            packages,
            versions,
            pub.get("source_ids"),
            version_override=pub.get("version"),
        )
        account = normalize_text(pub.get("publisher") or pub.get("account") or pub.get("publisher_account"))
        if account:
            add_unique(packages[pid]["publisher_candidates"], account)
        publishers.append({
            "publisher_id": normalize_text(pub.get("publisher_id")) or stable_id("PUB", pid, account, vid or ""),
            "package_id": pid,
            "package_version_id": vid,
            "account": account or None,
            "published_at": parse_time(pub.get("published_at")),
            "source_ids": [normalize_text(x) for x in pub.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": ["Publisher is not automatically code author, maintainer, project owner, or legal owner."],
        })

    for m in manifest.get("maintainers", []) or []:
        pid, vid = ensure_ref_package(
            m.get("package") or m.get("package_ref"),
            m.get("ecosystem", "unknown"),
            m.get("registry", "unknown"),
            packages,
            versions,
            m.get("source_ids"),
            version_override=m.get("version"),
        )
        account = normalize_text(m.get("maintainer") or m.get("account") or m.get("login"))
        if account:
            add_unique(packages[pid]["maintainer_candidates"], account)
        maintainers.append({
            "maintainer_id": normalize_text(m.get("maintainer_id")) or stable_id("MAINT", pid, account, vid or ""),
            "package_id": pid,
            "package_version_id": vid,
            "account": account or None,
            "role": normalize_text(m.get("role", "MAINTAINER")).upper(),
            "valid_from": parse_time(m.get("valid_from")),
            "valid_to": parse_time(m.get("valid_to")),
            "source_ids": [normalize_text(x) for x in m.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": ["Maintainer role is project role, not employment, legal ownership, or real-person certainty."],
        })

    for t in manifest.get("ownership_transfers", []) or []:
        pid, vid = ensure_ref_package(
            t.get("package") or t.get("package_ref"),
            t.get("ecosystem", "unknown"),
            t.get("registry", "unknown"),
            packages,
            versions,
            t.get("source_ids"),
            version_override=t.get("version"),
        )
        transfers.append({
            "transfer_id": normalize_text(t.get("transfer_id")) or stable_id("TRANSFER", pid, t.get("from"), t.get("to")),
            "package_id": pid,
            "package_version_id": vid,
            "from_account": normalize_text(t.get("from") or t.get("from_account")) or None,
            "to_account": normalize_text(t.get("to") or t.get("to_account")) or None,
            "transferred_at": parse_time(t.get("transferred_at") or t.get("effective_at")),
            "evidence": normalize_text(t.get("evidence")) or None,
            "source_ids": [normalize_text(x) for x in t.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Ownership transfer may be legitimate succession, acquisition, abandonment, community takeover, or compromise report.",
                "Transfer alone does not establish malicious takeover.",
            ],
        })

    return publishers, maintainers, transfers


# --------------------------------------------------------------------
# Dependency sources: manifests / lockfiles / SBOM / VEX / applications
# --------------------------------------------------------------------

def normalize_dep_type(value: Any) -> str:
    s = normalize_text(value).upper().replace("-", "_").replace(" ", "_")
    return DEPENDENCY_TYPE_ALIASES.get(s, s or "UNKNOWN")


def resolve_parent(
    application_id: Any,
    package_ref: Any,
    ecosystem: str,
    registry: str,
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
    source_ids: Optional[List[str]] = None,
) -> Tuple[str, str]:
    app = normalize_text(application_id)
    if app:
        return "APPLICATION", app
    if package_ref:
        pid, _ = ensure_ref_package(package_ref, ecosystem, registry, packages, versions, source_ids)
        return "PACKAGE", pid
    return "ROOT", "ROOT"


def parse_manifest_content(content: Any, ecosystem: str, registry: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    s = normalize_text(content)
    if not s:
        return out

    if s.startswith("{"):
        try:
            data = json.loads(s)
        except Exception:
            return out
        sections = {
            "dependencies": "RUNTIME",
            "devDependencies": "DEVELOPMENT",
            "peerDependencies": "PEER",
            "optionalDependencies": "OPTIONAL",
        }
        for sec, typ in sections.items():
            for name, rng in (data.get(sec) or {}).items():
                out.append({
                    "package": {"ecosystem": ecosystem, "registry": registry, "name": name},
                    "version_range": rng if isinstance(rng, str) else json_safe(rng),
                    "type": typ,
                })
        return out

    # Very small requirements-like parser.
    for line in s.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", line)
        if m:
            out.append({
                "package": {"ecosystem": ecosystem or "pypi", "registry": registry, "name": m.group(1)},
                "version_range": normalize_text(m.group(2)) or None,
                "type": "RUNTIME",
            })
    return out


def ingest_manifests(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    edges: List[Dict[str, Any]] = []
    for mf in manifest.get("manifests", []) or []:
        eco = normalize_text(mf.get("ecosystem", "unknown")).lower() or "unknown"
        reg = normalize_text(mf.get("registry", "unknown")).lower() or "unknown"
        source_ids = [normalize_text(x) for x in mf.get("source_ids", []) or [] if normalize_text(x)]
        parent_type, parent_id = resolve_parent(
            mf.get("application_id"),
            mf.get("package") or mf.get("root_package"),
            eco,
            reg,
            packages,
            versions,
            source_ids,
        )
        deps = list(mf.get("dependencies", []) or [])
        if mf.get("content"):
            deps.extend(parse_manifest_content(mf.get("content"), eco, reg))

        for d in deps:
            child_ref = d.get("package") or d.get("ref") or d.get("name")
            if not child_ref:
                continue
            child_pid, _ = ensure_ref_package(
                child_ref,
                eco,
                reg,
                packages,
                versions,
                d.get("source_ids") or source_ids,
            )
            edges.append({
                "dependency_id": stable_id(
                    "DEP",
                    parent_type,
                    parent_id,
                    child_pid,
                    d.get("version_range") or d.get("range") or "",
                    normalize_dep_type(d.get("type") or d.get("dependency_type")),
                ),
                "parent_type": parent_type,
                "parent_id": parent_id,
                "child_package_id": child_pid,
                "requested_version_range": normalize_text(d.get("version_range") or d.get("range")) or None,
                "resolved_version": normalize_text(d.get("resolved_version")) or None,
                "dependency_type": normalize_dep_type(d.get("type") or d.get("dependency_type")),
                "directness": "DIRECT",
                "dependency_depth": 1,
                "optional": bool(d.get("optional")),
                "environment": normalize_text(d.get("environment")) or None,
                "source_ids": list(dict.fromkeys((d.get("source_ids") or []) + source_ids)),
                "evidence_ids": [normalize_text(x) for x in d.get("evidence_ids", []) or [] if normalize_text(x)],
                "confidence_score": clamp(float(d.get("confidence", mf.get("confidence", 0.70)))),
                "evidence_kind": "MANIFEST",
                "limitations": [
                    "Manifest expresses requested constraints, not resolved or deployed versions.",
                ],
            })
    return edges


def ingest_lockfiles(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[Tuple[str, str], Set[str]]]:
    edges: List[Dict[str, Any]] = []
    resolved_by_app: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

    for lf in manifest.get("lockfiles", []) or []:
        eco = normalize_text(lf.get("ecosystem", "unknown")).lower() or "unknown"
        reg = normalize_text(lf.get("registry", "unknown")).lower() or "unknown"
        source_ids = [normalize_text(x) for x in lf.get("source_ids", []) or [] if normalize_text(x)]
        parent_type, parent_id = resolve_parent(
            lf.get("application_id"),
            lf.get("package") or lf.get("root_package"),
            eco,
            reg,
            packages,
            versions,
            source_ids,
        )
        deps = list(lf.get("resolved_dependencies", []) or [])

        for d in deps:
            child_ref = d.get("package") or d.get("ref") or d.get("name")
            if not child_ref:
                continue
            child_ver = normalize_text(d.get("version")) or None
            child_pid, child_vid = ensure_ref_package(
                child_ref,
                eco,
                reg,
                packages,
                versions,
                d.get("source_ids") or source_ids,
                version_override=child_ver,
            )
            edges.append({
                "dependency_id": stable_id("DEP", parent_type, parent_id, child_pid, child_ver or "", "LOCKFILE"),
                "parent_type": parent_type,
                "parent_id": parent_id,
                "child_package_id": child_pid,
                "requested_version_range": normalize_text(d.get("requested_version_range")) or None,
                "resolved_version": child_ver,
                "dependency_type": normalize_dep_type(d.get("type") or d.get("dependency_type")),
                "directness": "DIRECT",
                "dependency_depth": 1,
                "optional": bool(d.get("optional")),
                "environment": normalize_text(d.get("environment")) or None,
                "integrity_hash": normalize_text(d.get("integrity_hash") or d.get("hash")) or None,
                "source_ids": list(dict.fromkeys((d.get("source_ids") or []) + source_ids)),
                "evidence_ids": [normalize_text(x) for x in d.get("evidence_ids", []) or [] if normalize_text(x)],
                "confidence_score": clamp(float(d.get("confidence", lf.get("confidence", 0.76)))),
                "evidence_kind": "LOCKFILE",
                "limitations": [
                    "Lockfile represents a resolved build/configuration state, not necessarily deployed production reality.",
                ],
            })
            if parent_type == "APPLICATION" and child_ver:
                resolved_by_app[(parent_id, child_pid)].add(child_ver)

            for sub in d.get("dependencies", []) or []:
                if isinstance(sub, dict):
                    sub_ref = sub.get("package") or sub.get("ref") or sub.get("name")
                    sub_ver = normalize_text(sub.get("version")) or None
                else:
                    sub_ref = sub
                    sub_ver = None
                if not sub_ref:
                    continue
                sub_pid, _ = ensure_ref_package(
                    sub_ref,
                    eco,
                    reg,
                    packages,
                    versions,
                    source_ids,
                    version_override=sub_ver,
                )
                edges.append({
                    "dependency_id": stable_id("DEP", "PACKAGE", child_pid, sub_pid, sub_ver or "", "LOCKFILE_TRANSITIVE"),
                    "parent_type": "PACKAGE",
                    "parent_id": child_pid,
                    "child_package_id": sub_pid,
                    "requested_version_range": None,
                    "resolved_version": sub_ver,
                    "dependency_type": normalize_dep_type(sub.get("type") if isinstance(sub, dict) else "UNKNOWN"),
                    "directness": "TRANSITIVE",
                    "dependency_depth": 2,
                    "optional": bool(sub.get("optional")) if isinstance(sub, dict) else False,
                    "environment": normalize_text(sub.get("environment")) if isinstance(sub, dict) else None,
                    "integrity_hash": normalize_text(sub.get("integrity_hash") or sub.get("hash")) if isinstance(sub, dict) else None,
                    "source_ids": source_ids,
                    "evidence_ids": [],
                    "confidence_score": clamp(float(lf.get("confidence", 0.72))),
                    "evidence_kind": "LOCKFILE",
                    "limitations": ["Transitive lockfile edge may be environment/build specific."],
                })
                if parent_type == "APPLICATION" and sub_ver:
                    resolved_by_app[(parent_id, sub_pid)].add(sub_ver)

    return edges, dict(resolved_by_app)


def ingest_sboms(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[Tuple[str, str], Set[str]]]:
    edges: List[Dict[str, Any]] = []
    sboms: List[Dict[str, Any]] = []
    component_versions: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

    for sb in manifest.get("sboms", []) or []:
        eco = normalize_text(sb.get("ecosystem", "unknown")).lower() or "unknown"
        reg = normalize_text(sb.get("registry", "unknown")).lower() or "unknown"
        source_ids = [normalize_text(x) for x in sb.get("source_ids", []) or [] if normalize_text(x)]
        parent_type, parent_id = resolve_parent(
            sb.get("application_id") or sb.get("build_id"),
            sb.get("package") or sb.get("root_package"),
            eco,
            reg,
            packages,
            versions,
            source_ids,
        )
        comps = sb.get("components", []) or []
        ref_to_pid: Dict[str, str] = {}

        for comp in comps:
            ref = comp.get("package") or comp.get("ref") or comp.get("purl") or comp.get("name")
            if not ref:
                continue
            ver = normalize_text(comp.get("version")) or None
            pid, vid = ensure_ref_package(
                ref,
                eco,
                reg,
                packages,
                versions,
                comp.get("source_ids") or source_ids,
                version_override=ver,
            )
            key = normalize_text(ref) or pid
            ref_to_pid[key] = pid
            if ver and parent_type == "APPLICATION":
                component_versions[(parent_id, pid)].add(ver)
            if vid:
                for lic in comp.get("licenses", []) or []:
                    lic_text = normalize_text(lic.get("license") if isinstance(lic, dict) else lic)
                    if lic_text:
                        add_unique(versions[vid]["licenses_observed"], lic_text)

        for dep in sb.get("dependencies", []) or []:
            pref = dep.get("ref")
            ppid = ref_to_pid.get(normalize_text(pref))
            if not ppid and pref:
                ppid, _ = ensure_ref_package(pref, eco, reg, packages, versions, source_ids)
            if not ppid:
                continue
            for cref in dep.get("dependsOn", []) or []:
                cpid = ref_to_pid.get(normalize_text(cref))
                if not cpid and cref:
                    cpid, _ = ensure_ref_package(cref, eco, reg, packages, versions, source_ids)
                if not cpid:
                    continue
                edges.append({
                    "dependency_id": stable_id("DEP", "PACKAGE", ppid, cpid, "SBOM"),
                    "parent_type": "PACKAGE",
                    "parent_id": ppid,
                    "child_package_id": cpid,
                    "requested_version_range": None,
                    "resolved_version": None,
                    "dependency_type": "UNKNOWN",
                    "directness": "UNKNOWN",
                    "dependency_depth": None,
                    "optional": False,
                    "environment": None,
                    "source_ids": source_ids,
                    "evidence_ids": [normalize_text(x) for x in dep.get("evidence_ids", []) or [] if normalize_text(x)],
                    "confidence_score": clamp(float(sb.get("confidence", 0.68))),
                    "evidence_kind": "SBOM",
                    "limitations": [
                        "SBOM dependency edges may be build-specific, incomplete, or stale.",
                    ],
                })

        sboms.append({
            "sbom_id": normalize_text(sb.get("sbom_id")) or stable_id("SBOM", parent_id, sb.get("format", "unknown")),
            "application_or_build_id": parent_id if parent_type == "APPLICATION" else None,
            "root_package_id": parent_id if parent_type == "PACKAGE" else None,
            "format": normalize_text(sb.get("format", "unknown")).lower(),
            "generated_at": parse_time(sb.get("generated_at")),
            "document_hash": normalize_text(sb.get("document_hash")) or None,
            "component_count": len(comps),
            "source_ids": source_ids,
            "limitations": list(sb.get("limitations", []) or []) + [
                "SBOM is evidence, not deployed truth.",
                "SBOM may omit vendored code, dynamic plugins, runtime downloads, or optional components.",
            ],
        })

    return edges, sboms, dict(component_versions)


def ingest_vex(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    vex_records: List[Dict[str, Any]] = []
    for v in manifest.get("vex_records", []) or []:
        pid, vid = ensure_ref_package(
            v.get("package") or v.get("package_ref"),
            v.get("ecosystem", "unknown"),
            v.get("registry", "unknown"),
            packages,
            versions,
            v.get("source_ids"),
            version_override=v.get("version"),
        )
        rec = {
            "vex_id": normalize_text(v.get("vex_id")) or stable_id("VEX", pid, v.get("vulnerability_id", ""), vid or ""),
            "package_id": pid,
            "package_version_id": vid,
            "vulnerability_id": normalize_text(v.get("vulnerability_id") or v.get("cve")) or None,
            "status": normalize_text(v.get("status", "UNKNOWN")).upper(),
            "justification": normalize_text(v.get("justification")) or None,
            "statement": normalize_text(v.get("statement")) or None,
            "timestamp": parse_time(v.get("timestamp")),
            "source_ids": [normalize_text(x) for x in v.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "VEX is source assertion; applicability may require independent technical review.",
            ],
        }
        vex_records.append(rec)
        if vid:
            add_unique(versions[vid]["vex_records"], rec)
    return vex_records


def ingest_applications(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[Tuple[str, str], Set[str]], List[Dict[str, Any]]]:
    apps: List[Dict[str, Any]] = []
    deployed_by_app: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    edges: List[Dict[str, Any]] = []

    for app in manifest.get("applications", []) or []:
        app_id = normalize_text(app.get("application_id") or app.get("id"))
        if not app_id:
            continue
        envs = app.get("environments", {}) or {}
        for env, data in envs.items():
            env_u = normalize_text(env).upper()
            for dp in (data or {}).get("deployed_packages", []) or []:
                ref = dp.get("package") or dp.get("ref") or dp.get("name")
                if not ref:
                    continue
                ver = normalize_text(dp.get("version")) or None
                pid, vid = ensure_ref_package(
                    ref,
                    dp.get("ecosystem", app.get("ecosystem", "unknown")),
                    dp.get("registry", app.get("registry", "unknown")),
                    packages,
                    versions,
                    dp.get("source_ids") or app.get("source_ids"),
                    version_override=ver,
                )
                if vid:
                    add_unique(versions[vid]["deployed_environments"], env_u)
                    t = parse_time(dp.get("deployed_at") or dp.get("observed_at"))
                    if t:
                        versions[vid]["deployed_times"].append(t)
                if ver:
                    deployed_by_app[(app_id, pid)].add(ver)
                edges.append({
                    "dependency_id": stable_id("DEP", "APPLICATION", app_id, pid, ver or "", "DEPLOYED"),
                    "parent_type": "APPLICATION",
                    "parent_id": app_id,
                    "child_package_id": pid,
                    "requested_version_range": None,
                    "resolved_version": ver,
                    "dependency_type": "RUNTIME",
                    "directness": "UNKNOWN",
                    "dependency_depth": None,
                    "optional": False,
                    "environment": env_u,
                    "source_ids": list(dict.fromkeys((dp.get("source_ids") or []) + (app.get("source_ids") or []))),
                    "evidence_ids": [normalize_text(x) for x in dp.get("evidence_ids", []) or [] if normalize_text(x)],
                    "confidence_score": clamp(float(dp.get("confidence", 0.80))),
                    "evidence_kind": "DEPLOYED_INVENTORY",
                    "limitations": [
                        "Deployed inventory evidence is stronger than lockfile/SBOM for runtime state, but still source-bound.",
                    ],
                })
        apps.append({
            "application_id": app_id,
            "name": normalize_text(app.get("name")) or app_id,
            "environments": sorted({normalize_text(k).upper() for k in envs.keys()}),
            "source_ids": [normalize_text(x) for x in app.get("source_ids", []) or [] if normalize_text(x)],
        })

    return apps, dict(deployed_by_app), edges


def ingest_releases(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
    artifacts: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    releases: List[Dict[str, Any]] = []
    for rel in manifest.get("releases", []) or []:
        eco = normalize_text(rel.get("ecosystem", "unknown")).lower() or "unknown"
        reg = normalize_text(rel.get("registry", "unknown")).lower() or "unknown"
        pid, vid = ensure_ref_package(
            rel.get("package") or rel.get("package_ref"),
            eco,
            reg,
            packages,
            versions,
            rel.get("source_ids"),
            version_override=rel.get("version"),
        )
        if rel.get("version") and not vid:
            vid = ensure_version(versions, pid, rel.get("version"), source_ids=rel.get("source_ids"))
        if vid:
            ver = versions[vid]
            published_at = parse_time(rel.get("published_at") or rel.get("release_time"))
            if published_at:
                ver["release_time"] = ver["release_time"] or published_at
            if rel.get("yanked"):
                ver["yanked"] = True
                ver["yanked_at"] = ver["yanked_at"] or parse_time(rel.get("yanked_at"))
            if rel.get("deprecated"):
                ver["deprecated"] = True
                ver["deprecated_at"] = ver["deprecated_at"] or parse_time(rel.get("deprecated_at"))
            if rel.get("repository_revision"):
                ver["repository_revision"] = normalize_text(rel.get("repository_revision")) or ver["repository_revision"]
            if rel.get("signature_state"):
                ver["signature_state"] = normalize_text(rel.get("signature_state")).upper() or ver["signature_state"]
            if rel.get("attestation_state"):
                ver["attestation_state"] = normalize_text(rel.get("attestation_state")).upper() or ver["attestation_state"]
            if rel.get("provenance") is not None:
                ver["provenance"] = rel.get("provenance")

        art_ids = []
        for a in rel.get("artifacts", []) or []:
            aid = ensure_artifact(
                artifacts,
                vid,
                artifact_id=a.get("artifact_id"),
                filename=a.get("filename") or a.get("name"),
                artifact_type=a.get("artifact_type") or a.get("kind"),
                size=a.get("size"),
                hashes=a.get("hashes"),
                platform=a.get("platform"),
                architecture=a.get("architecture"),
                signature=a.get("signature"),
                source_ids=a.get("source_ids") or rel.get("source_ids"),
            )
            if aid:
                art_ids.append(aid)
                if vid:
                    add_unique(versions[vid]["artifact_ids"], aid)

        releases.append({
            "release_id": normalize_text(rel.get("release_id")) or stable_id("REL", pid, rel.get("version", ""), rel.get("published_at", "")),
            "package_id": pid,
            "package_version_id": vid,
            "version": normalize_text(rel.get("version")) or None,
            "published_at": parse_time(rel.get("published_at") or rel.get("release_time")),
            "publisher_account": normalize_text(rel.get("publisher") or rel.get("publisher_account")) or None,
            "repository_revision": normalize_text(rel.get("repository_revision")) or None,
            "artifact_ids": art_ids,
            "signature_state": normalize_text(rel.get("signature_state")).upper() or "UNKNOWN",
            "attestation_state": normalize_text(rel.get("attestation_state")).upper() or "UNKNOWN",
            "yanked": bool(rel.get("yanked")),
            "yanked_at": parse_time(rel.get("yanked_at")),
            "deprecated": bool(rel.get("deprecated")),
            "deprecated_at": parse_time(rel.get("deprecated_at")),
            "release_notes": normalize_text(rel.get("release_notes")) or None,
            "source_ids": [normalize_text(x) for x in rel.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Release publication does not prove installation, execution, or deployment.",
            ],
        })
    return releases


def ingest_advisories(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    advisories: List[Dict[str, Any]] = []
    for a in manifest.get("security_advisories", []) or []:
        pid, vid = ensure_ref_package(
            a.get("package") or a.get("package_ref"),
            a.get("ecosystem", "unknown"),
            a.get("registry", "unknown"),
            packages,
            versions,
            a.get("source_ids"),
            version_override=a.get("version"),
        )
        advisories.append({
            "advisory_id": normalize_text(a.get("advisory_id")) or stable_id("ADV", pid, a.get("cve", ""), a.get("ghsa", "")),
            "package_id": pid,
            "package_version_id": vid,
            "version": normalize_text(a.get("version")) or None,
            "cve": normalize_text(a.get("cve")) or None,
            "ghsa": normalize_text(a.get("ghsa")) or None,
            "advisory_url": normalize_text(a.get("advisory_url")) or None,
            "affected_versions": normalize_text(a.get("affected_versions")) or None,
            "fixed_versions": normalize_text(a.get("fixed_versions")) or None,
            "published_at": parse_time(a.get("published_at")),
            "severity": normalize_text(a.get("severity", "UNKNOWN")).upper(),
            "source_ids": [normalize_text(x) for x in a.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Advisory does not prove exploitation, deployment, or applicability without VULNINT analysis.",
            ],
        })
    return advisories


def ingest_malicious_reports(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    reports: List[Dict[str, Any]] = []
    for r in manifest.get("malicious_package_reports", []) or []:
        pid, vid = ensure_ref_package(
            r.get("package") or r.get("package_ref"),
            r.get("ecosystem", "unknown"),
            r.get("registry", "unknown"),
            packages,
            versions,
            r.get("source_ids"),
            version_override=r.get("version"),
        )
        rep = {
            "report_id": normalize_text(r.get("report_id")) or stable_id("MAL", pid, r.get("version", ""), r.get("source_id", "")),
            "package_id": pid,
            "package_version_id": vid,
            "version": normalize_text(r.get("version")) or None,
            "artifact_hash": normalize_text(r.get("artifact_hash")) or None,
            "claim": normalize_text(r.get("claim") or r.get("summary")) or "MALICIOUS_PACKAGE_REPORTED",
            "reported_at": parse_time(r.get("reported_at")),
            "source_id": normalize_text(r.get("source_id")) or None,
            "source_ids": [normalize_text(x) for x in r.get("source_ids", []) or [] if normalize_text(x)],
            "status": normalize_text(r.get("status", "REPORTED")).upper(),
            "limitations": [
                "Malicious report is source claim until supported by independent evidence.",
                "PACKAGEINT does not execute or install packages to verify maliciousness.",
            ],
        }
        reports.append(rep)
        if vid:
            add_unique(versions[vid]["malicious_context"], rep)
        else:
            add_unique(packages[pid]["malicious_context"], rep)
    return reports


def ingest_known_official(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    official: List[Dict[str, Any]] = []
    for o in manifest.get("known_official_packages", []) or []:
        ref = o.get("package") or {
            "ecosystem": o.get("ecosystem", "unknown"),
            "registry": o.get("registry", "unknown"),
            "namespace": o.get("namespace"),
            "name": o.get("name"),
        }
        pid, _ = ensure_ref_package(
            ref,
            o.get("ecosystem", "unknown"),
            o.get("registry", "unknown"),
            packages,
            versions,
            o.get("source_ids"),
        )
        pkg = packages[pid]
        official.append({
            "package_id": pid,
            "ecosystem": pkg["ecosystem"],
            "namespace": pkg["namespace"],
            "name": pkg["name"],
            "normalized_name": pkg["normalized_name"],
            "official_url": normalize_text(o.get("official_url")) or None,
            "source_ids": [normalize_text(x) for x in o.get("source_ids", []) or [] if normalize_text(x)],
        })
    return official


def ingest_internal_context(
    manifest: Dict[str, Any],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    internal: List[Dict[str, Any]] = []
    for ip in manifest.get("internal_packages", []) or []:
        pid, vid = ensure_ref_package(
            ip.get("package") or ip.get("package_ref"),
            ip.get("ecosystem", "unknown"),
            ip.get("registry", "private"),
            packages,
            versions,
            ip.get("source_ids"),
            version_override=ip.get("version"),
        )
        pkg = packages[pid]
        pkg["registry_type"] = normalize_text(ip.get("registry_type", "INTERNAL")).upper()
        pkg["resolver_precedence"] = normalize_text(ip.get("resolver_precedence")) or pkg.get("resolver_precedence")
        internal.append({
            "internal_package_id": normalize_text(ip.get("internal_package_id")) or stable_id("INT", pid),
            "package_id": pid,
            "package_version_id": vid,
            "registry_type": pkg["registry_type"],
            "resolver_precedence": pkg["resolver_precedence"],
            "source_ids": [normalize_text(x) for x in ip.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Internal package names can reveal products/projects/architecture; retain within authorization scope.",
            ],
        })
    return internal


def enrich_registry_types(
    packages: Dict[str, Dict[str, Any]],
    registries: Dict[str, Dict[str, Any]],
    internal: List[Dict[str, Any]],
) -> None:
    for pid, pkg in packages.items():
        reg = registries.get(pkg.get("registry", ""))
        if reg:
            pkg["registry_type"] = reg.get("registry_type") or pkg.get("registry_type")
    for i in internal:
        pkg = packages.get(i["package_id"])
        if pkg:
            pkg["registry_type"] = i.get("registry_type") or pkg.get("registry_type")
            pkg["resolver_precedence"] = i.get("resolver_precedence") or pkg.get("resolver_precedence")


# --------------------------------------------------------------------
# Version range / SemVer helpers
# --------------------------------------------------------------------

def parse_semver(value: Any) -> Optional[Tuple[int, int, int, str]]:
    s = normalize_text(value).lstrip("vV")
    if not s:
        return None
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$", s)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4) or ""
    m = re.match(r"^(\d+)\.(\d+)$", s)
    if m:
        return int(m.group(1)), int(m.group(2)), 0, ""
    m = re.match(r"^(\d+)$", s)
    if m:
        return int(m.group(1)), 0, 0, ""
    return None


def semver_tuple(v: Any) -> Optional[Tuple[int, int, int, int, str]]:
    p = parse_semver(v)
    if not p:
        return None
    major, minor, patch, pre = p
    # Empty pre-release sorts after pre-release in simplified model.
    return major, minor, patch, 0 if pre else 1, pre


def semver_compare(a: Any, b: Any) -> Optional[int]:
    ta = semver_tuple(a)
    tb = semver_tuple(b)
    if ta is None or tb is None:
        return None
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def version_equal(a: Any, b: Any) -> bool:
    cmp = semver_compare(a, b)
    if cmp is not None:
        return cmp == 0
    return normalize_text(a).lower() == normalize_text(b).lower()


def _single_range(version: str, expr: str) -> Optional[bool]:
    e = normalize_text(expr)
    if not e:
        return None
    if e in {"*", "latest", "any", "x"}:
        return True

    if e.startswith("^"):
        base = e[1:]
        cmp_base = semver_compare(version, base)
        bv = parse_semver(base)
        if cmp_base is None or not bv:
            return None
        if cmp_base < 0:
            return False
        major, minor, patch, _ = bv
        if major > 0:
            upper = f"{major + 1}.0.0"
        elif minor > 0:
            upper = f"0.{minor + 1}.0"
        else:
            upper = f"0.0.{patch + 1}"
        cmp_upper = semver_compare(version, upper)
        return None if cmp_upper is None else cmp_upper < 0

    if e.startswith("~"):
        base = e[1:]
        cmp_base = semver_compare(version, base)
        bv = parse_semver(base)
        if cmp_base is None or not bv:
            return None
        if cmp_base < 0:
            return False
        major, minor, _, _ = bv
        upper = f"{major}.{minor + 1}.0"
        cmp_upper = semver_compare(version, upper)
        return None if cmp_upper is None else cmp_upper < 0

    m = re.match(r"^(>=|<=|>|<|=|==)\s*(.+)$", e)
    if m:
        op = m.group(1)
        other = normalize_text(m.group(2))
        cmp = semver_compare(version, other)
        if cmp is None:
            if op in {"=", "=="}:
                return version_equal(version, other)
            return None
        if op == ">=":
            return cmp >= 0
        if op == "<=":
            return cmp <= 0
        if op == ">":
            return cmp > 0
        if op == "<":
            return cmp < 0
        if op in {"=", "=="}:
            return cmp == 0

    m = re.match(r"^(\d+)(?:\.x|\.\*)$", e)
    if m:
        major = int(m.group(1))
        lo = semver_compare(version, f"{major}.0.0")
        hi = semver_compare(version, f"{major + 1}.0.0")
        if lo is None or hi is None:
            return None
        return lo >= 0 and hi < 0

    m = re.match(r"^(\d+)\.(\d+)(?:\.x|\.\*)$", e)
    if m:
        major = int(m.group(1))
        minor = int(m.group(2))
        lo = semver_compare(version, f"{major}.{minor}.0")
        hi = semver_compare(version, f"{major}.{minor + 1}.0")
        if lo is None or hi is None:
            return None
        return lo >= 0 and hi < 0

    if re.fullmatch(r"[vV]?[0-9][0-9A-Za-z.\-+]*", e):
        return version_equal(version, e)

    return None


def version_in_range(version: Any, expr: Any) -> Optional[bool]:
    v = normalize_text(version)
    e = normalize_text(expr)
    if not v or not e:
        return None
    parts = [p.strip() for p in re.split(r",|\s+&&\s+", e) if p.strip()]
    if not parts:
        return None
    results = [_single_range(v, p) for p in parts]
    if any(r is False for r in results):
        return False
    if any(r is None for r in results):
        return None
    return True


# --------------------------------------------------------------------
# Dependency graph analysis
# --------------------------------------------------------------------

def compute_dependency_analysis(edges: List[Dict[str, Any]], packages: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    adj: Dict[str, List[str]] = defaultdict(list)
    pack_adj: Dict[str, List[str]] = defaultdict(list)
    roots: Set[str] = set()

    for e in edges:
        parent_key = f"{e['parent_type']}:{e['parent_id']}"
        child = e["child_package_id"]
        adj[parent_key].append(child)
        if e["parent_type"] == "PACKAGE":
            pack_adj[e["parent_id"]].append(child)
        if e["parent_type"] == "APPLICATION":
            roots.add(parent_key)

    paths: List[Dict[str, Any]] = []
    min_depths: Dict[str, int] = defaultdict(lambda: 999)
    direct_ids: Set[str] = set()

    for root in sorted(roots)[:200]:
        q = deque([(root, 0, [root])])
        seen: Dict[str, int] = {}
        while q:
            node, depth, path = q.popleft()
            if node.startswith("PACKAGE:"):
                pid = node.split(":", 1)[1]
                if depth < min_depths[pid]:
                    min_depths[pid] = depth
                if depth == 1:
                    direct_ids.add(pid)
                if len(paths) < 2000:
                    paths.append({
                        "root": root,
                        "package_id": pid,
                        "depth": depth,
                        "path": path + [pid],
                    })
            for child in adj.get(node, []):
                child_node = f"PACKAGE:{child}"
                if child_node not in seen or seen[child_node] > depth + 1:
                    seen[child_node] = depth + 1
                    if len(path) < 12:
                        q.append((child_node, depth + 1, path + [child]))

    # Cycle detection among package-to-package edges.
    color: Dict[str, int] = defaultdict(int)
    cycles: List[List[str]] = []

    def dfs(u: str, stack: List[str]) -> None:
        color[u] = 1
        stack.append(u)
        for v in pack_adj.get(u, []):
            if color[v] == 1:
                try:
                    idx = stack.index(v)
                    cycles.append(stack[idx:] + [v])
                except ValueError:
                    cycles.append([u, v, u])
            elif color[v] == 0:
                dfs(v, stack)
        stack.pop()
        color[u] = 2

    for u in list(pack_adj.keys()):
        if color[u] == 0:
            dfs(u, [])

    return {
        "roots": sorted(roots),
        "paths": paths[:2000],
        "min_depths": {k: v for k, v in min_depths.items() if v < 999},
        "direct_package_ids": sorted(direct_ids),
        "cycles": unique_preserve(cycles)[:200],
        "edge_count": len(edges),
        "limitations": [
            "Dependency graph is evidence-bound and may be incomplete across environments/builds.",
            "Presence in graph does not prove runtime reachability or exploitability.",
        ],
    }


# --------------------------------------------------------------------
# Security / typosquat / dependency confusion / contradictions
# --------------------------------------------------------------------

def map_vulnerabilities(advisories: List[Dict[str, Any]], versions: Dict[str, Dict[str, Any]]) -> None:
    for adv in advisories:
        pid = adv["package_id"]
        for vid, ver in versions.items():
            if ver["package_id"] != pid:
                continue
            affected = version_in_range(ver["version"], adv.get("affected_versions"))
            fixed = version_in_range(ver["version"], adv.get("fixed_versions"))
            status = "UNKNOWN"
            confidence = 0.35
            if affected is True:
                status = "AFFECTED_CANDIDATE"
                confidence = 0.70
            elif fixed is True:
                status = "FIXED_CANDIDATE"
                confidence = 0.70
            elif affected is False:
                status = "NOT_AFFECTED_CANDIDATE"
                confidence = 0.50
            add_unique(ver["vulnerability_context"], {
                "advisory_id": adv["advisory_id"],
                "cve": adv.get("cve"),
                "ghsa": adv.get("ghsa"),
                "status": status,
                "confidence": confidence,
                "affected_versions": adv.get("affected_versions"),
                "fixed_versions": adv.get("fixed_versions"),
                "limitations": ["Final applicability/reachability requires VULNINT."],
            })


def levenshtein(a: str, b: str, max_dist: int = 3) -> Optional[int]:
    if abs(len(a) - len(b)) > max_dist:
        return None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        min_row = min(cur)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            min_row = min(min_row, cur[j])
        if min_row > max_dist:
            return None
        prev = cur
    return prev[-1]


def detect_typosquat(
    packages: Dict[str, Dict[str, Any]],
    official: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    official_ids = {o["package_id"] for o in official}
    out: List[Dict[str, Any]] = []
    for pid, pkg in packages.items():
        if pid in official_ids:
            continue
        for off in official:
            if off["ecosystem"] != pkg["ecosystem"]:
                continue
            on = normalize_text(off.get("normalized_name"))
            pn = normalize_text(pkg.get("normalized_name"))
            if not on or not pn:
                continue
            state = None
            distance = None
            if on == pn:
                if normalize_text(off.get("namespace") or "") != normalize_text(pkg.get("namespace") or ""):
                    state = "NAME_COLLISION"
                else:
                    continue
            else:
                distance = levenshtein(on, pn, max_dist=2)
                if distance is not None and distance <= 2:
                    state = "TYPOSQUAT_CANDIDATE"
            if not state:
                continue
            cand = {
                "typosquat_id": stable_id("TYPO", pid, off["package_id"], state),
                "package_id": pid,
                "resembles_official_package_id": off["package_id"],
                "ecosystem": pkg["ecosystem"],
                "name": pkg["name"],
                "official_name": off["name"],
                "state": state,
                "edit_distance": distance,
                "namespace_match": normalize_text(pkg.get("namespace") or "") == normalize_text(off.get("namespace") or ""),
                "limitations": [
                    "Name similarity is not maliciousness.",
                    "May be fork, plugin, wrapper, legitimate unrelated package, or collision.",
                    "PACKAGEINT does not register, publish, or test lookalike packages.",
                ],
            }
            out.append(cand)
            add_unique(pkg["typosquat_context"], cand)
    return out


def detect_dependency_confusion(
    packages: Dict[str, Dict[str, Any]],
    registries: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    public_by_norm: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for pid, pkg in packages.items():
        reg = registries.get(pkg.get("registry", ""), {})
        reg_type = normalize_text(pkg.get("registry_type") or reg.get("registry_type") or "UNKNOWN").upper()
        if reg_type in {"PUBLIC", "UNKNOWN"}:
            public_by_norm[(pkg["ecosystem"], pkg["normalized_name"])].append(pid)

    out: List[Dict[str, Any]] = []
    for pid, pkg in packages.items():
        reg = registries.get(pkg.get("registry", ""), {})
        reg_type = normalize_text(pkg.get("registry_type") or reg.get("registry_type") or "UNKNOWN").upper()
        if reg_type not in PRIVATE_REGISTRY_TYPES:
            continue
        key = (pkg["ecosystem"], pkg["normalized_name"])
        pubs = [x for x in public_by_norm.get(key, []) if x != pid]
        if not pubs:
            continue
        precedence = normalize_text(pkg.get("resolver_precedence")) or None
        risk = {
            "confusion_id": stable_id("CONF", pid, *pubs),
            "internal_package_id": pid,
            "public_package_ids": pubs,
            "ecosystem": pkg["ecosystem"],
            "normalized_name": pkg["normalized_name"],
            "state": "DEPENDENCY_CONFUSION_RISK_CANDIDATE",
            "factors": [
                "private/internal package identifier also exists in public registry context",
                "resolver precedence unclear" if not precedence else f"declared resolver precedence: {precedence}",
            ],
            "defensive_recommendations": [
                "Review registry precedence and scoped/private-first resolution policy.",
                "Verify internal package namespace ownership and allowlisted registries.",
                "Do not test by publishing/registering packages.",
            ],
            "limitations": [
                "This is defensive risk analysis only.",
                "Same identifier does not prove exploitation or malicious intent.",
                "PACKAGEINT does not register, publish, or test dependency-confusion conditions.",
            ],
        }
        out.append(risk)
        add_unique(pkg["dependency_confusion_context"], risk)
    return out


def detect_contradictions(
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
    resolved_by_app: Dict[Tuple[str, str], Set[str]],
    deployed_by_app: Dict[Tuple[str, str], Set[str]],
    component_versions: Dict[Tuple[str, str], Set[str]],
) -> List[Dict[str, Any]]:
    contr: List[Dict[str, Any]] = []

    for e in edges:
        req = e.get("requested_version_range")
        res = e.get("resolved_version")
        if req and res:
            ok = version_in_range(res, req)
            if ok is False:
                contr.append({
                    "contradiction_id": stable_id("CTR", "requested_resolved", e["dependency_id"]),
                    "type": "REQUESTED_RESOLVED_MISMATCH",
                    "severity": "MATERIAL",
                    "dependency_id": e["dependency_id"],
                    "package_id": e["child_package_id"],
                    "detail": f"Resolved version {res} does not satisfy requested range {req}.",
                    "possible_causes": [
                        "stale manifest/lockfile pairing",
                        "resolver override",
                        "different environment",
                        "metadata error",
                        "package identity mismatch",
                    ],
                })

    for (app, pid), deps in deployed_by_app.items():
        res = resolved_by_app.get((app, pid), set())
        if res and deps and not (res & deps):
            contr.append({
                "contradiction_id": stable_id("CTR", "deployed_resolved", app, pid),
                "type": "DEPLOYED_VS_RESOLVED_MISMATCH",
                "severity": "MATERIAL",
                "application_id": app,
                "package_id": pid,
                "detail": f"Deployed versions {sorted(deps)} do not intersect resolved versions {sorted(res)}.",
                "possible_causes": [
                    "lockfile stale",
                    "different build/deployment pipeline",
                    "runtime patching/backport",
                    "wrong application identity",
                    "partial rollout",
                ],
            })

    for (app, pid), comps in component_versions.items():
        res = resolved_by_app.get((app, pid), set())
        if res and comps and not (res & comps):
            contr.append({
                "contradiction_id": stable_id("CTR", "sbom_resolved", app, pid),
                "type": "SBOM_VS_LOCKFILE_MISMATCH",
                "severity": "MATERIAL",
                "application_id": app,
                "package_id": pid,
                "detail": f"SBOM versions {sorted(comps)} do not intersect lockfile versions {sorted(res)}.",
                "possible_causes": [
                    "SBOM stale",
                    "different build",
                    "SBOM incomplete",
                    "lockfile not used for build",
                    "package identity mismatch",
                ],
            })

    for pid, pkg in packages.items():
        urls = [u for u in pkg.get("repository_references", []) if u]
        if len(set(urls)) > 1:
            contr.append({
                "contradiction_id": stable_id("CTR", "repository_refs", pid),
                "type": "REPOSITORY_REFERENCE_CONFLICT",
                "severity": "MATERIAL",
                "package_id": pid,
                "detail": f"Package has multiple distinct repository references: {sorted(set(urls))}.",
                "possible_causes": [
                    "repository migration",
                    "fork/mirror metadata",
                    "stale registry metadata",
                    "multiple packages collapsed by name",
                    "monorepo/package split",
                ],
            })

    for vid, ver in versions.items():
        pkg = packages.get(ver["package_id"], {})
        pl = normalize_text(pkg.get("license_metadata")).lower()
        vl = [normalize_text(x).lower() for x in ver.get("licenses_observed", []) if normalize_text(x)]
        if pl and vl and all(x != pl for x in vl):
            contr.append({
                "contradiction_id": stable_id("CTR", "license", vid),
                "type": "LICENSE_CONFLICT",
                "severity": "MATERIAL",
                "package_id": ver["package_id"],
                "package_version_id": vid,
                "detail": f"Package metadata license '{pl}' conflicts with observed license(s) {vl}.",
                "possible_causes": ["dual licensing", "stale metadata", "vendored code", "SBOM parsing artifact"],
                "handoff": "LEGALINT",
            })

        yanked_at = ver.get("yanked_at")
        if yanked_at:
            for t in ver.get("deployed_times", []):
                if isinstance(t, datetime) and t > yanked_at:
                    contr.append({
                        "contradiction_id": stable_id("CTR", "yanked_deployed", vid, iso(t)),
                        "type": "YANKED_VERSION_DEPLOYED_AFTER_YANK",
                        "severity": "MATERIAL",
                        "package_version_id": vid,
                        "detail": f"Version yanked at {iso(yanked_at)} but deployed evidence exists at {iso(t)}.",
                        "possible_causes": [
                            "existing installations remain after yank",
                            "mirror/proxy cache",
                            "deployment evidence time wrong",
                            "yank metadata lag",
                        ],
                    })

    return contr


# --------------------------------------------------------------------
# Hypotheses / ACH / gaps / actions / handoffs
# --------------------------------------------------------------------

def generate_hypotheses(
    contradictions: List[Dict[str, Any]],
    typosquats: List[Dict[str, Any]],
    confusion: List[Dict[str, Any]],
    malicious_reports: List[Dict[str, Any]],
    advisories: List[Dict[str, Any]],
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    hyp: List[Dict[str, Any]] = []

    def add(
        subject_type: str,
        subject_id: str,
        category: str,
        statement: str,
        support: List[str],
        opposition: List[str],
        unknowns: List[str],
        falsification: List[str],
    ) -> None:
        hyp.append({
            "hypothesis_id": stable_id("HYP", subject_type, subject_id, category, statement),
            "subject_type": subject_type,
            "subject_id": subject_id,
            "category": category,
            "statement": statement,
            "support": support,
            "opposition": opposition,
            "unknowns": unknowns,
            "falsification_conditions": falsification,
            "status": "CANDIDATE",
        })

    for c in contradictions:
        sid = c["contradiction_id"]
        add("CONTRADICTION", sid, "DATA_ARTIFACT",
            "Conflict may be caused by stale lockfile/SBOM/deployment evidence.",
            [c.get("type", "")],
            ["Independent current evidence may confirm real discrepancy."],
            ["Current build/deploy records", "pipeline timestamps"],
            ["Fresh authorized inventory matches the conflicting evidence."])
        add("CONTRADICTION", sid, "IDENTITY",
            "Conflict may be caused by wrong package/application identity resolution.",
            ["Package name collisions are common across ecosystems."],
            ["PURL/registry metadata may support identity."],
            ["ecosystem/registry/namespace mapping"],
            ["Authoritative registry metadata confirms distinct identities."])
        add("CONTRADICTION", sid, "BENIGN_CONTEXT",
            "Conflict may reflect dev/test/build-only dependency or partial rollout.",
            ["Dependency type/environment may explain difference."],
            ["Production inventory may still include package."],
            ["environment scope", "feature flags"],
            ["Runtime inventory shows package absent in production."])
        if any(k in normalize_text(c.get("type", "")).lower() for k in ["yanked", "malicious", "compromise"]):
            add("CONTRADICTION", sid, "SERIOUS_CANDIDATE",
                "Actual compromise or malicious release remains a candidate requiring independent evidence.",
                ["Lifecycle/security anomaly present."],
                ["Benign operational explanations not exhausted."],
                ["publisher/maintainer compromise evidence", "artifact behavior"],
                ["Independent provenance/signature/artifact evidence shows benign release."])

    for t in typosquats:
        sid = t["typosquat_id"]
        add("TYPOSQUAT", sid, "BENIGN",
            "Similar package name may be legitimate plugin, wrapper, fork, or unrelated package.",
            ["Name similarity alone is weak evidence."],
            ["Publisher/repository/provenance differ from official package."],
            ["maintainer intent", "package usage context"],
            ["Official project documents relationship or package is removed/quarantined."])
        add("TYPOSQUAT", sid, "SERIOUS_CANDIDATE",
            "Package may be impersonation/typosquat candidate requiring defensive review.",
            [f"state={t['state']}", f"edit_distance={t.get('edit_distance')}"],
            ["No behavioral or publisher evidence yet."],
            ["publisher identity", "artifact provenance", "install-script behavior"],
            ["Package is verified as official/authorized or benign."])

    for d in confusion:
        sid = d["confusion_id"]
        add("DEPENDENCY_CONFUSION", sid, "CONFIGURATION",
            "Resolver precedence or registry scoping may be misconfigured defensively.",
            d.get("factors", []),
            ["Same identifier may be coincidental across registries."],
            ["actual resolver configuration", "private registry policy"],
            ["Authorized configuration review shows private-first/scoped resolution."])
        add("DEPENDENCY_CONFUSION", sid, "SERIOUS_CANDIDATE",
            "Dependency-confusion exposure may be exploitable if resolver precedence is unsafe.",
            ["Internal/public identifier collision present."],
            ["No exploitation was performed or assisted."],
            ["build logs", "resolver precedence", "registry allowlists"],
            ["Resolution evidence shows internal package always preferred and public name unavailable/unresolved."])

    for r in malicious_reports:
        sid = r["report_id"]
        add("MALICIOUS_REPORT", sid, "DATA_ARTIFACT",
            "Malicious report may be false positive, name collision, or version mismatch.",
            ["Single feed claim is not independent evidence."],
            ["Multiple independent authoritative reports may exist."],
            ["package identity", "version/artifact scope"],
            ["Identity/version resolution shows report refers to different package/version."])
        add("MALICIOUS_REPORT", sid, "SERIOUS_CANDIDATE",
            "Malicious package/release remains a candidate for MALINT/incident review.",
            [r.get("claim", "")],
            ["PACKAGEINT does not execute/install to verify."],
            ["artifact behavior", "publisher compromise", "dependency path exposure"],
            ["Sandbox/incident evidence shows benign behavior or report retracted."])

    for adv in advisories:
        sid = adv["advisory_id"]
        add("VULNERABILITY", sid, "BENIGN_CONTEXT",
            "Advisory may not apply due to dev-only/optional/unreachable/non-deployed version.",
            ["Advisory is version/range bound."],
            ["Affected version may be present in build evidence."],
            ["deployment state", "reachability"],
            ["Authorized inventory shows affected version absent/not reachable."])
        add("VULNERABILITY", sid, "SERIOUS_CANDIDATE",
            "Vulnerable version may be present in some evidence context, requiring VULNINT applicability analysis.",
            [f"affected_versions={adv.get('affected_versions')}"],
            ["Presence does not prove exploitation."],
            ["reachability", "runtime version", "platform/backport status"],
            ["VULNINT determines not affected/fixed/not reachable."])

    return hyp[:2000]


def build_ach_stub(hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_subject: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for h in hypotheses:
        by_subject[(h.get("subject_type", "UNKNOWN"), h.get("subject_id", "UNKNOWN"))].append(h)

    out = []
    for (stype, sid), hs in list(by_subject.items())[:300]:
        out.append({
            "ach_id": stable_id("ACH", stype, sid),
            "subject_type": stype,
            "subject_id": sid,
            "hypotheses": [
                {
                    "hypothesis_id": h["hypothesis_id"],
                    "category": h["category"],
                    "statement": h["statement"],
                    "support": h.get("support", []),
                    "opposition": h.get("opposition", []),
                    "falsification_conditions": h.get("falsification_conditions", []),
                    "status": h.get("status"),
                }
                for h in hs
            ],
            "limitations": [
                "ACH stub is analytical support only.",
                "No autonomous accusation, maliciousness verdict, or punitive action is implied.",
            ],
        })
    return out


def build_gaps(
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
    sboms: List[Dict[str, Any]],
    advisories: List[Dict[str, Any]],
    malicious_reports: List[Dict[str, Any]],
    typosquats: List[Dict[str, Any]],
    confusion: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    for pid, pkg in packages.items():
        if pkg.get("ecosystem") in {None, "", "unknown"} or pkg.get("registry") in {None, "", "unknown"}:
            gaps.append({
                "gap_id": stable_id("GAP", "identity", pid),
                "type": "PACKAGE_IDENTITY_AMBIGUOUS",
                "importance": "HIGH",
                "package_id": pid,
                "recommended_source": "Official registry metadata, PURL, lockfile, SBOM, or authorized inventory.",
                "specialist": "PACKAGEINT",
                "expected_information_value": "Prevent false package identity/version mapping.",
            })
        if not pkg.get("repository_references"):
            gaps.append({
                "gap_id": stable_id("GAP", "repo", pid),
                "type": "REPOSITORY_UNRESOLVED",
                "importance": "MEDIUM",
                "package_id": pid,
                "recommended_source": "Registry metadata, official project docs, release provenance.",
                "specialist": "REPOINT / PACKAGEINT",
                "expected_information_value": "Connect package to source repository without assuming.",
            })
        if not pkg.get("publisher_candidates") and not pkg.get("maintainer_candidates"):
            gaps.append({
                "gap_id": stable_id("GAP", "people", pid),
                "type": "PUBLISHER_MAINTAINER_UNRESOLVED",
                "importance": "MEDIUM",
                "package_id": pid,
                "recommended_source": "Registry publisher metadata, release signatures, governance docs.",
                "specialist": "PACKAGEINT / REPOINT",
                "expected_information_value": "Support provenance and maintainer-change review.",
            })

    for vid, ver in versions.items():
        if not ver.get("release_time"):
            gaps.append({
                "gap_id": stable_id("GAP", "release_time", vid),
                "type": "RELEASE_TIME_UNKNOWN",
                "importance": "MEDIUM",
                "package_version_id": vid,
                "recommended_source": "Registry release metadata, CI/CD build metadata.",
                "specialist": "PACKAGEINT",
                "expected_information_value": "Improve temporal dependency intelligence.",
            })
        if normalize_text(ver.get("signature_state")).upper() in {"", "UNKNOWN", "UNSIGNED"}:
            gaps.append({
                "gap_id": stable_id("GAP", "signature", vid),
                "type": "SIGNATURE_UNKNOWN",
                "importance": "MEDIUM",
                "package_version_id": vid,
                "recommended_source": "Registry signature metadata, release attestation, artifact signature.",
                "specialist": "PACKAGEINT / SUPPLYCHAININT",
                "expected_information_value": "Assess provenance strength without claiming security.",
            })
        if not ver.get("provenance"):
            gaps.append({
                "gap_id": stable_id("GAP", "provenance", vid),
                "type": "PROVENANCE_MISSING",
                "importance": "MEDIUM",
                "package_version_id": vid,
                "recommended_source": "SLSA-like attestation, build metadata, signed release chain.",
                "specialist": "PACKAGEINT / SUPPLYCHAININT",
                "expected_information_value": "Strengthen software provenance assessment.",
            })
        if any(vc.get("status") == "UNKNOWN" for vc in ver.get("vulnerability_context", [])):
            gaps.append({
                "gap_id": stable_id("GAP", "vuln_map", vid),
                "type": "VULNERABILITY_MAPPING_AMBIGUOUS",
                "importance": "HIGH",
                "package_version_id": vid,
                "recommended_source": "Authoritative advisory, PURL mapping, distribution backport metadata.",
                "specialist": "VULNINT",
                "expected_information_value": "Avoid false CVE/package mapping.",
            })
        if ver.get("malicious_context"):
            gaps.append({
                "gap_id": stable_id("GAP", "malicious", vid),
                "type": "MALICIOUSNESS_DISPUTED",
                "importance": "HIGH",
                "package_version_id": vid,
                "recommended_source": "Independent malicious-package reports, artifact behavior, publisher compromise evidence.",
                "specialist": "MALINT / INCIDENTINT",
                "expected_information_value": "Move from report claim to supported/ dismissed maliciousness.",
            })

    for sb in sboms:
        gen = sb.get("generated_at")
        if isinstance(gen, datetime) and (now - gen).days > 180:
            gaps.append({
                "gap_id": stable_id("GAP", "sbom_stale", sb["sbom_id"]),
                "type": "SBOM_POSSIBLY_STALE",
                "importance": "MEDIUM",
                "sbom_id": sb["sbom_id"],
                "recommended_source": "Fresh build-time SBOM, artifact manifest, deployed runtime inventory.",
                "specialist": "PACKAGEINT / SUPPLYCHAININT",
                "expected_information_value": "Prevent stale SBOM from being treated as current deployment.",
            })

    for t in typosquats:
        gaps.append({
            "gap_id": stable_id("GAP", "typo", t["typosquat_id"]),
            "type": "TYPOSQUAT_UNRESOLVED",
            "importance": "MEDIUM",
            "typosquat_id": t["typosquat_id"],
            "recommended_source": "Official project/vendor documentation, publisher/repository comparison.",
            "specialist": "PACKAGEINT / MALINT",
            "expected_information_value": "Distinguish legitimate similarity from impersonation candidate.",
        })

    for d in confusion:
        gaps.append({
            "gap_id": stable_id("GAP", "confusion", d["confusion_id"]),
            "type": "DEPENDENCY_CONFUSION_UNRESOLVED",
            "importance": "HIGH",
            "confusion_id": d["confusion_id"],
            "recommended_source": "Authorized resolver configuration, registry allowlist, build logs.",
            "specialist": "PACKAGEINT / SUPPLYCHAININT",
            "expected_information_value": "Defensively confirm or mitigate resolver precedence risk.",
        })

    for c in contradictions:
        gaps.append({
            "gap_id": stable_id("GAP", "contradiction", c["contradiction_id"]),
            "type": "PACKAGE_CONTRADICTION_UNRESOLVED",
            "importance": "HIGH" if c.get("severity") == "MATERIAL" else "MEDIUM",
            "contradiction_id": c["contradiction_id"],
            "recommended_source": "Authoritative registry metadata, current lockfile/SBOM, deployed inventory.",
            "specialist": "PACKAGEINT / HUMAN_REVIEW",
            "expected_information_value": "Resolve conflicting package/version/deployment claims.",
        })

    return gaps[:1000]


def build_next_actions(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions = []
    priority_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for g in gaps:
        if g["type"] == "PACKAGE_IDENTITY_AMBIGUOUS":
            action = "Resolve ecosystem/registry/namespace/PURL before treating package name as identity."
        elif g["type"] == "REPOSITORY_UNRESOLVED":
            action = "Retrieve official registry metadata and project documentation to map package to repository."
        elif g["type"] == "PUBLISHER_MAINTAINER_UNRESOLVED":
            action = "Retrieve publisher/maintainer metadata and release provenance; do not infer real-person identity."
        elif g["type"] == "RELEASE_TIME_UNKNOWN":
            action = "Retrieve release publication metadata or build timestamps for temporal validation."
        elif g["type"] == "SIGNATURE_UNKNOWN":
            action = "Check artifact/release signature or attestation metadata; signed ≠ benign."
        elif g["type"] == "PROVENANCE_MISSING":
            action = "Retrieve SLSA-like attestation/build provenance where available."
        elif g["type"] == "VULNERABILITY_MAPPING_AMBIGUOUS":
            action = "Handoff advisory/package mapping to VULNINT for applicability and reachability."
        elif g["type"] == "MALICIOUSNESS_DISPUTED":
            action = "Handoff malicious-package report to MALINT/INCIDENTINT; do not execute or install package."
        elif g["type"] == "SBOM_POSSIBLY_STALE":
            action = "Refresh SBOM from current build/deployed inventory before supply-chain conclusions."
        elif g["type"] == "TYPOSQUAT_UNRESOLVED":
            action = "Compare publisher/repository/provenance defensively; do not publish/test lookalikes."
        elif g["type"] == "DEPENDENCY_CONFUSION_UNRESOLVED":
            action = "Review resolver precedence and registry allowlists defensively; do not test by publishing."
        elif g["type"] == "PACKAGE_CONTRADICTION_UNRESOLVED":
            action = "Resolve contradiction using authoritative current evidence; preserve historical states."
        else:
            action = "Gather additional authorized package intelligence evidence."

        actions.append({
            "action": action,
            "gap_id": g.get("gap_id"),
            "priority": g.get("importance", "MEDIUM"),
            "expected_information_value": g.get("expected_information_value"),
            "prohibited_alternatives": [
                "Do not publish, register, or upload malicious/typosquat packages.",
                "Do not perform dependency-confusion exploitation.",
                "Do not execute/install suspicious packages.",
                "Do not use registry tokens or signing keys.",
                "Do not tamper with lockfiles/SBOMs/build pipelines.",
            ],
        })
    actions.sort(key=lambda x: priority_map.get(x.get("priority", "LOW"), 9))
    return actions[:300]


def build_handoffs(
    packages: Dict[str, Dict[str, Any]],
    versions: Dict[str, Dict[str, Any]],
    advisories: List[Dict[str, Any]],
    malicious_reports: List[Dict[str, Any]],
    typosquats: List[Dict[str, Any]],
    confusion: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    dependency_analysis: Dict[str, Any],
) -> List[Dict[str, Any]]:
    hands: List[Dict[str, Any]] = []
    seen = set()

    def add(spec: str, reason: str, payload: Dict[str, Any]) -> None:
        key = (spec, json.dumps(json_safe(payload), sort_keys=True))
        if key in seen:
            return
        seen.add(key)
        hands.append({"specialist": spec, "reason": reason, "payload": payload})

    if advisories:
        add("VULNINT", "Vulnerability applicability/reachability requires VULNINT.", {
            "advisory_ids": [a["advisory_id"] for a in advisories[:100]],
        })
    if malicious_reports:
        add("MALINT / INCIDENTINT", "Malicious-package reports require behavior/incident analysis without execution by PACKAGEINT.", {
            "report_ids": [r["report_id"] for r in malicious_reports[:100]],
        })
    if typosquats:
        add("MALINT / PACKAGEINT_REVIEW", "Typosquat candidates require defensive publisher/provenance review.", {
            "typosquat_ids": [t["typosquat_id"] for t in typosquats[:100]],
        })
    if confusion:
        add("SUPPLYCHAININT / CI_SECURITY", "Dependency-confusion risk requires defensive resolver/registry policy review.", {
            "confusion_ids": [d["confusion_id"] for d in confusion[:100]],
        })
    if any(c.get("type") == "REPOSITORY_REFERENCE_CONFLICT" for c in contradictions):
        add("REPOINT", "Repository/package mapping conflicts require repository provenance analysis.", {
            "contradiction_ids": [c["contradiction_id"] for c in contradictions if c.get("type") == "REPOSITORY_REFERENCE_CONFLICT"][:100],
        })
    if any(c.get("type") == "LICENSE_CONFLICT" for c in contradictions):
        add("LEGALINT", "License conflicts require legal review.", {
            "contradiction_ids": [c["contradiction_id"] for c in contradictions if c.get("type") == "LICENSE_CONFLICT"][:100],
        })
    if dependency_analysis.get("cycles") or len(dependency_analysis.get("paths", [])) > 100:
        add("SUPPLYCHAININT", "Dependency graph scale/cycles require supply-chain propagation/criticality analysis.", {
            "cycle_count": len(dependency_analysis.get("cycles", [])),
            "path_count": len(dependency_analysis.get("paths", [])),
        })
    if any(ver.get("malicious_context") for ver in versions.values()):
        add("HUMAN_REVIEW", "Version-level malicious context requires authorized human review before consequential action.", {
            "package_version_ids": [vid for vid, ver in versions.items() if ver.get("malicious_context")][:100],
        })
    return hands



def compute_supply_chain_context(edges, dependency_analysis, versions):
    """Summarize submitted dependency paths, without claiming exploitability."""
    dependent_count = Counter(e["child_package_id"] for e in edges)
    concentration = [{"package_id": pid, "dependent_edge_count": count}
                     for pid, count in dependent_count.most_common(200)]
    affected = {version["package_id"] for version in versions.values()
                if any(item.get("status") == "AFFECTED_CANDIDATE"
                       for item in version.get("vulnerability_context", []))}
    propagation = [{"root": path.get("root"), "package_id": path["package_id"],
                    "path": list(path.get("path", [])), "depth": path.get("depth"),
                    "status": "DEPENDENCY_EXPOSURE_CANDIDATE",
                    "runtime_reachability_verified": False}
                   for path in dependency_analysis.get("paths", [])[:2000]
                   if path.get("package_id") in affected]
    return concentration, propagation


def analyze_packageint_manifest(manifest):
    """Complete the upload's ingest/analysis pipeline for supplied records only."""
    blocked = policy_screen(manifest)
    approved, reasons = authorization_check(manifest)
    if blocked or not approved:
        return {"case_id": manifest.get("case_id"), "status": "BLOCKED_POLICY",
                "policy_violations": blocked + reasons, "network_calls": 0}
    registries = ingest_registries(manifest)
    packages, versions, artifacts = ingest_packages(manifest, registries)
    sources = ingest_sources(manifest)
    roots = build_source_roots(sources)
    repositories = ingest_repositories(manifest)
    publishers, maintainers, transfers = ingest_people(manifest, packages, versions)
    edges = ingest_manifests(manifest, packages, versions)
    lock_edges, resolved = ingest_lockfiles(manifest, packages, versions)
    sbom_edges, sboms, components = ingest_sboms(manifest, packages, versions)
    vex = ingest_vex(manifest, packages, versions)
    applications, deployed, app_edges = ingest_applications(manifest, packages, versions)
    edges.extend(lock_edges + sbom_edges + app_edges)
    releases = ingest_releases(manifest, packages, versions, artifacts)
    advisories = ingest_advisories(manifest, packages, versions)
    malicious = ingest_malicious_reports(manifest, packages, versions)
    official = ingest_known_official(manifest, packages, versions)
    internal = ingest_internal_context(manifest, packages, versions)
    enrich_registry_types(packages, registries, internal)
    dependency = compute_dependency_analysis(edges, packages)
    map_vulnerabilities(advisories, versions)
    typosquats = detect_typosquat(packages, official)
    confusion = detect_dependency_confusion(packages, registries)
    contradictions = detect_contradictions(packages, versions, edges, resolved, deployed, components)
    hypotheses = generate_hypotheses(contradictions, typosquats, confusion, malicious,
                                     advisories, packages, versions)
    gaps = build_gaps(packages, versions, sboms, advisories, malicious, typosquats,
                      confusion, contradictions)
    handoffs = build_handoffs(packages, versions, advisories, malicious, typosquats,
                              confusion, contradictions, dependency)
    concentration, propagation = compute_supply_chain_context(edges, dependency, versions)
    return json_safe({
        "case_id": manifest.get("case_id"), "status": "ANALYSIS_DRAFT",
        "module_version": VERSION, "network_calls": 0,
        "registries": registries, "packages": packages, "versions": versions,
        "artifacts": artifacts, "sources": sources, "source_families": roots,
        "repositories": repositories, "publishers": publishers,
        "maintainers": maintainers, "transfers": transfers,
        "applications": applications, "releases": releases, "vex": vex,
        "sboms": sboms, "advisories": advisories, "malicious_reports": malicious,
        "dependencies": dependency, "concentration": concentration,
        "propagation_candidates": propagation, "typosquat_candidates": typosquats,
        "dependency_confusion_candidates": confusion, "contradictions": contradictions,
        "hypotheses": hypotheses, "knowledge_gaps": gaps,
        "next_actions": build_next_actions(gaps), "specialist_handoffs": handoffs,
        "source_authenticity_verified": False, "exploitation_verified": False,
        "requires_human_review": True,
    })
