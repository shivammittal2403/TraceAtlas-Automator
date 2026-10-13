#!/usr/bin/env python3
"""
TRACEATLAS REPOINT — Safe Python Starter Implementation

Purpose:
  Evidence-first repository / software-provenance intelligence pipeline.

Hard boundaries enforced in code:
  - Does NOT access private repositories without authorization.
  - Does NOT use stolen tokens, cookies, SSH keys, or credentials.
  - Does NOT bypass MFA/SSO/branch protection/access control.
  - Does NOT submit malicious commits/PRs/MRs.
  - Does NOT poison dependencies, publish malicious packages, typosquat,
    or perform dependency confusion.
  - Does NOT modify CI/CD pipelines or trigger malicious builds.
  - Does NOT harvest, use, or validate secrets.
  - Does NOT execute untrusted repository code, install scripts, containers,
    binaries, notebooks, or model artifacts.
  - Treats repository content as untrusted data.
  - Treats account/hosting owner as distinct from legal owner.
  - Treats contributor, maintainer, code owner, reviewer, and employee as
    separate roles.
  - Treats commit, merge, release, build, and deployment as separate stages.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

VERSION = "0.1.0-repoint-safe-starter"
FAR_FUTURE = datetime(9999, 12, 31, tzinfo=timezone.utc)

# --------------------------------------------------------------------
# Policy / authorization constants
# --------------------------------------------------------------------

ALLOWED_SCOPES = {
    "public_and_authorized_records",
    "authorized_private_repositories",
    "authorized_case_evidence",
    "provided_records_only",
}

PROHIBITED_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)\b(access|open|clone|read)\s+(private|internal)\s+repo(sitory)?\b.*\b(without|no)\s+authoriz"),
        "UNAUTHORIZED_PRIVATE_REPOSITORY_ACCESS",
    ),
    (
        re.compile(r"(?i)\b(stolen|leaked|exposed)\s+(pat|token|cookie|ssh key|credential)s?\b.*\b(use|login|authenticate|access)\b"),
        "STOLEN_CREDENTIAL_USE",
    ),
    (
        re.compile(r"(?i)\b(bypass|avoid|defeat)\s+(mfa|2fa|sso|branch protection|access control|secret scanning)\b"),
        "SECURITY_CONTROL_BYPASS_REQUEST",
    ),
    (
        re.compile(r"(?i)\b(malicious|poison(ed)?|typosquat|dependency confusion)\b.*\b(commit|pr|pull request|merge request|package|dependency|ci/cd|pipeline)\b"),
        "SUPPLY_CHAIN_ATTACK_REQUEST",
    ),
    (
        re.compile(r"(?i)\b(validate|test|verify|use)\s+(secret|token|key|credential|password)\b.*\b(api|login|authenticate|cloud|database|service)\b"),
        "SECRET_VALIDATION_REQUEST",
    ),
    (
        re.compile(r"(?i)\b(execute|run|install|build|import|source|launch)\s+(untrusted|unknown|suspicious|malicious)\s+(code|script|repo|repository|container|binary|notebook|model)\b"),
        "UNTRUSTED_CODE_EXECUTION_REQUEST",
    ),
    (
        re.compile(r"(?i)\b(exploit|attack|weaponize|payload|shell|reverse shell|backdoor|Persistence)\b.*\b(repo|repository|ci/cd|pipeline|package|maintainer)\b"),
        "REPOSITORY_EXPLOITATION_REQUEST",
    ),
    (
        re.compile(r"(?i)\b(doxx?|identify real person| deanonymi[sz]e|home address|personal email)\b.*\b(contributor|maintainer|user|developer)\b"),
        "DOXXING_OR_REAL_PERSON_IDENTIFICATION",
    ),
]

SOURCE_RELIABILITY: Dict[str, float] = {
    "platform_api": 0.90,
    "git_object": 0.92,
    "signed_commit": 0.88,
    "signed_tag": 0.88,
    "official_release": 0.86,
    "package_registry": 0.84,
    "sbom": 0.72,
    "ci_metadata": 0.74,
    "security_advisory": 0.82,
    "project_documentation": 0.62,
    "official_org_page": 0.78,
    "public_repo_page": 0.60,
    "public_user_profile": 0.45,
    "third_party_database": 0.40,
    "media_blog": 0.45,
    "anonymous_source": 0.15,
    "unknown": 0.30,
}

HIGH_AUTHORITY_SOURCE_TYPES = {
    "platform_api",
    "git_object",
    "signed_commit",
    "signed_tag",
    "official_release",
    "package_registry",
    "security_advisory",
    "official_org_page",
}

TEST_SECRET_HINTS = {
    "example",
    "test",
    "dummy",
    "sample",
    "placeholder",
    "changeme",
    "change-me",
    "your-",
    "your_",
    "xxx",
    "redacted",
    "fake",
    "mock",
    "stub",
}

SECRET_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS_ACCESS_KEY_ID_CANDIDATE"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GITHUB_PERSONAL_ACCESS_TOKEN_CANDIDATE"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{80}"), "GITHUB_FINE_GRAINED_PAT_CANDIDATE"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "SLACK_TOKEN_CANDIDATE"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "PRIVATE_KEY_HEADER_CANDIDATE"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT_CANDIDATE"),
    (
        re.compile(
            r"(?i)\b(api[_-]?key|token|secret|password|passwd|pwd|access[_-]?key|private[_-]?key)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.\/+=]{12,})"
        ),
        "GENERIC_SECRET_ASSIGNMENT_CANDIDATE",
    ),
]

LICENSE_SIGNATURES: List[Tuple[str, Tuple[str, ...]]] = [
    ("MIT", ("mit license", "permission is hereby granted, free of charge")),
    ("Apache-2.0", ("apache license", "version 2.0", "http://www.apache.org/licenses/LICENSE-2.0")),
    ("GPL-3.0-only", ("gnu general public license", "version 3")),
    ("GPL-3.0-or-later", ("gnu general public license", "either version 3", "or any later version")),
    ("BSD-3-Clause", ("bsd 3-clause", "neither the name of the copyright holder")),
    ("BSD-2-Clause", ("bsd 2-clause", "simplified bsd license")),
    ("MPL-2.0", ("mozilla public license", "version 2.0")),
    ("ISC", ("isc license",)),
]

DEPRECATION_HINTS = (
    "deprecated",
    "no longer maintained",
    "not maintained",
    "use instead",
    "successor project",
    "archived",
    "end of life",
    "eol",
)

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


def collapse_ws(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


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


def redact_secret_match(value: str) -> str:
    s = normalize_text(value)
    if not s:
        return ""
    if len(s) <= 10:
        return "*" * len(s)
    return s[:4] + "..." + s[-4:]


def lower_set(values: Iterable[Any]) -> Set[str]:
    return {normalize_text(v).lower() for v in values if normalize_text(v)}


# --------------------------------------------------------------------
# Policy / authorization / privacy
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


def privacy_config(manifest: Dict[str, Any]) -> Dict[str, Any]:
    auth = manifest.get("authorization", {}) or {}
    pc = dict(auth.get("privacy", {}) or manifest.get("privacy", {}) or {})
    pc.setdefault("minimize_personal_data", True)
    pc.setdefault("mask_emails", True)
    pc.setdefault("never_store_raw_secrets", True)
    return pc


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

    private_like = False
    for repo in manifest.get("repositories", []) or []:
        vis = normalize_text(repo.get("visibility", "")).upper()
        if vis in {"PRIVATE", "INTERNAL", "PRIVATE_AUTHORIZED", "INTERNAL_AUTHORIZED"}:
            private_like = True
            break

    if private_like and not auth.get("private_repositories_approved"):
        reasons.append("PRIVATE_REPOSITORY_ACCESS_NOT_APPROVED")

    return (len(reasons) == 0), reasons


# --------------------------------------------------------------------
# Source handling
# --------------------------------------------------------------------

def collect_referenced_source_ids(manifest: Dict[str, Any]) -> Set[str]:
    ids = set()
    for s in manifest.get("sources", []) or []:
        sid = normalize_text(s.get("source_id"))
        if sid:
            ids.add(sid)
    for bucket in (
        "repositories",
        "accounts",
        "commits",
        "branches",
        "tags",
        "releases",
        "packages",
        "dependencies",
        "sboms",
        "ci_workflows",
        "security_advisories",
        "repository_relationships",
        "control_eras",
        "maintainers",
        "codeowners",
    ):
        for item in manifest.get(bucket, []) or []:
            for sid in item.get("source_ids", []) or []:
                sid = normalize_text(sid)
                if sid:
                    ids.add(sid)
            sid = normalize_text(item.get("source_id"))
            if sid:
                ids.add(sid)
    return ids


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

    for sid in collect_referenced_source_ids(manifest):
        if sid not in sources:
            sources[sid] = {
                "source_id": sid,
                "source_type": "unknown",
                "upstream_source_id": None,
                "reliability": SOURCE_RELIABILITY["unknown"],
                "observed_at": None,
                "url": None,
                "limitations": ["Source referenced but not defined in manifest."],
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
    vals = []
    for sid in source_ids:
        vals.append(float(sources.get(sid, {}).get("reliability", SOURCE_RELIABILITY["unknown"])))
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
# Repository URL normalization
# --------------------------------------------------------------------

def infer_platform(host: str) -> str:
    h = normalize_text(host).lower()
    if "github" in h:
        return "github"
    if "gitlab" in h:
        return "gitlab"
    if "bitbucket" in h:
        return "bitbucket"
    if "azure" in h:
        return "azure_repos"
    if "sourcehut" in h or "sr.ht" in h:
        return "sourcehut"
    if "codeberg" in h:
        return "codeberg"
    if "gitea" in h or "forgejo" in h:
        return "gitea_or_forgejo"
    return "self_hosted_git"


def normalize_repository_url(value: Any) -> Dict[str, Any]:
    raw = normalize_text(value)
    out = {
        "raw_url": raw,
        "host": None,
        "namespace": None,
        "repository_name": None,
        "canonical_url": None,
        "platform": "unknown",
    }
    if not raw:
        return out

    m = re.match(r"^git@([^:]+):([^/]+)/(.+?)(?:\.git)?/?$", raw)
    if m:
        host = m.group(1).lower()
        namespace = m.group(2)
        name = m.group(3)
        out.update({
            "host": host,
            "namespace": namespace,
            "repository_name": name,
            "canonical_url": f"https://{host}/{namespace}/{name}",
            "platform": infer_platform(host),
        })
        return out

    working = raw
    if "://" not in working:
        working = "//" + working
    parsed = urlparse(working)
    host = (parsed.netloc or "").lower()
    path = parsed.path.strip("/")
    if not host and not path:
        return out

    parts = [p for p in path.split("/") if p]
    if parts and parts[-1].endswith(".git"):
        parts[-1] = parts[-1][:-4]

    if len(parts) >= 2:
        namespace = "/".join(parts[:-1])
        name = parts[-1]
    elif len(parts) == 1:
        namespace = ""
        name = parts[0]
    else:
        namespace = ""
        name = ""

    canonical = f"https://{host}/{namespace}/{name}".rstrip("/") if host else None
    out.update({
        "host": host or None,
        "namespace": namespace or None,
        "repository_name": name or None,
        "canonical_url": canonical,
        "platform": infer_platform(host) if host else "unknown",
    })
    return out


# --------------------------------------------------------------------
# Accounts / repositories
# --------------------------------------------------------------------

def ensure_account(
    accounts: Dict[str, Dict[str, Any]],
    account_id: Any,
    platform: Optional[str] = None,
    host: Optional[str] = None,
    account_type: str = "UNKNOWN",
    source_ids: Optional[List[str]] = None,
    reason: str = "",
) -> Optional[Dict[str, Any]]:
    aid = normalize_text(account_id)
    if not aid:
        return None
    if aid not in accounts:
        accounts[aid] = {
            "account_id": aid,
            "platform": normalize_text(platform or "unknown").lower(),
            "host": normalize_text(host or "").lower() or None,
            "login": aid,
            "display_name": None,
            "account_type": normalize_text(account_type).upper() or "UNKNOWN",
            "immutable_id": None,
            "created_at": None,
            "source_ids": list(dict.fromkeys(source_ids or [])),
            "limitations": [
                f"Account placeholder created because {reason}." if reason else "Account reference is not verified real-person identity.",
                "Account/hosting owner is not automatically legal owner.",
            ],
        }
    else:
        acc = accounts[aid]
        if platform and acc.get("platform") in {None, "", "unknown"}:
            acc["platform"] = normalize_text(platform).lower()
        if host and not acc.get("host"):
            acc["host"] = normalize_text(host).lower()
        if account_type and acc.get("account_type") == "UNKNOWN":
            acc["account_type"] = normalize_text(account_type).upper()
        for sid in source_ids or []:
            if sid not in acc["source_ids"]:
                acc["source_ids"].append(sid)
    return accounts[aid]


def ensure_repository(
    repos: Dict[str, Dict[str, Any]],
    repository_id: Any,
    reason: str = "",
) -> Dict[str, Any]:
    rid = normalize_text(repository_id)
    if rid in repos:
        return repos[rid]
    repos[rid] = {
        "repository_id": rid,
        "platform": "unknown",
        "host": None,
        "namespace": None,
        "owner_account": None,
        "repository_name": rid,
        "canonical_url": None,
        "visibility": "UNKNOWN",
        "access_state": "ACCESS_UNKNOWN",
        "default_branch": None,
        "created_at": None,
        "first_seen": None,
        "last_seen": None,
        "archived": False,
        "archived_at": None,
        "fork_state": "UNKNOWN",
        "mirror_state": "UNKNOWN",
        "upstream_repository": None,
        "license": None,
        "languages": [],
        "topics": [],
        "description": None,
        "homepage": None,
        "package_links": [],
        "organization_links": [],
        "source_ids": [],
        "confidence_score": 0.25,
        "limitations": [f"Placeholder repository created because {reason}." if reason else "Repository reference unresolved."],
    }
    return repos[rid]


def ingest_repositories(
    manifest: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    privacy_cfg: Dict[str, Any],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    repos: Dict[str, Dict[str, Any]] = {}
    accounts: Dict[str, Dict[str, Any]] = {}
    privacy_flags: List[Dict[str, Any]] = []

    auth = manifest.get("authorization", {}) or {}

    for idx, r in enumerate(manifest.get("repositories", []) or []):
        url_data = normalize_repository_url(
            r.get("canonical_url")
            or r.get("html_url")
            or r.get("clone_url")
            or r.get("repository_url")
            or r.get("url")
        )
        repo_id = normalize_text(r.get("repository_id")) or stable_id("REPO", url_data.get("canonical_url") or idx)
        visibility_raw = normalize_text(r.get("visibility", "PUBLIC")).upper()

        if visibility_raw in {"PRIVATE", "INTERNAL"}:
            if auth.get("private_repositories_approved"):
                visibility = visibility_raw + "_AUTHORIZED"
            else:
                visibility = "UNKNOWN"
                privacy_flags.append({
                    "repository_id": repo_id,
                    "type": "PRIVATE_REPOSITORY_VISIBILITY_MASKED",
                    "action": "NOT_ACCESSING_UNAUTHORIZED_PRIVATE_CONTENT",
                })
        else:
            visibility = visibility_raw or "PUBLIC"

        if visibility in {"PUBLIC"}:
            access_state = "ACCESS_PUBLIC"
        elif visibility in {"PRIVATE_AUTHORIZED", "INTERNAL_AUTHORIZED"}:
            access_state = "ACCESS_AUTHORIZED"
        else:
            access_state = "ACCESS_UNKNOWN"

        source_ids = [normalize_text(x) for x in r.get("source_ids", []) or [] if normalize_text(x)]
        owner_account = normalize_text(r.get("owner_account") or url_data.get("namespace")) or None
        if owner_account:
            ensure_account(
                accounts,
                owner_account,
                platform=url_data.get("platform"),
                host=url_data.get("host"),
                account_type=r.get("owner_account_type", "UNKNOWN"),
                source_ids=source_ids,
                reason="repository owner reference",
            )

        repos[repo_id] = {
            "repository_id": repo_id,
            "platform": normalize_text(r.get("platform") or url_data.get("platform") or "unknown").lower(),
            "host": normalize_text(r.get("host") or url_data.get("host") or "").lower() or None,
            "namespace": normalize_text(r.get("namespace") or url_data.get("namespace") or "") or None,
            "owner_account": owner_account,
            "repository_name": normalize_text(r.get("repository_name") or url_data.get("repository_name") or repo_id),
            "canonical_url": normalize_text(r.get("canonical_url") or url_data.get("canonical_url")) or None,
            "visibility": visibility,
            "access_state": access_state,
            "default_branch": normalize_text(r.get("default_branch")) or None,
            "created_at": parse_time(r.get("created_at")),
            "first_seen": parse_time(r.get("first_seen")),
            "last_seen": parse_time(r.get("last_seen")),
            "archived": bool(r.get("archived", False)),
            "archived_at": parse_time(r.get("archived_at")),
            "fork_state": normalize_text(r.get("fork_state", "UNKNOWN")).upper(),
            "mirror_state": normalize_text(r.get("mirror_state", "UNKNOWN")).upper(),
            "upstream_repository": normalize_text(r.get("upstream_repository")) or None,
            "license": normalize_text(r.get("license")) or None,
            "languages": [normalize_text(x) for x in r.get("languages", []) or [] if normalize_text(x)],
            "topics": [normalize_text(x) for x in r.get("topics", []) or [] if normalize_text(x)],
            "description": normalize_text(r.get("description")) or None,
            "homepage": normalize_text(r.get("homepage")) or None,
            "package_links": [normalize_text(x) for x in r.get("package_links", []) or [] if normalize_text(x)],
            "organization_links": [normalize_text(x) for x in r.get("organization_links", []) or [] if normalize_text(x)],
            "source_ids": source_ids,
            "confidence_score": clamp(float(r.get("confidence", 0.65))),
            "limitations": list(r.get("limitations", []) or []) + [
                "Repository hosting account is not automatically legal owner.",
                "Repository is not automatically project, product, or package.",
                "No network lookup or private access was performed.",
            ],
        }

    return repos, accounts, privacy_flags


def ingest_accounts(manifest: Dict[str, Any], accounts: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    for a in manifest.get("accounts", []) or []:
        aid = normalize_text(a.get("account_id") or a.get("login") or a.get("username"))
        if not aid:
            continue
        acc = ensure_account(
            accounts,
            aid,
            platform=a.get("platform"),
            host=a.get("host"),
            account_type=a.get("account_type", "UNKNOWN"),
            source_ids=[normalize_text(x) for x in a.get("source_ids", []) or [] if normalize_text(x)],
            reason="explicit account record",
        )
        if acc:
            acc["display_name"] = normalize_text(a.get("display_name")) or acc.get("display_name")
            acc["immutable_id"] = normalize_text(a.get("immutable_id")) or acc.get("immutable_id")
            acc["created_at"] = parse_time(a.get("created_at")) or acc.get("created_at")
            acc["limitations"] = list(dict.fromkeys(acc.get("limitations", []) + list(a.get("limitations", []) or [])))
    return accounts


# --------------------------------------------------------------------
# Secret scanning / redaction
# --------------------------------------------------------------------

def scan_secrets(text: Any, location: str, context: str = "") -> List[Dict[str, Any]]:
    s = normalize_text(text)
    if not s:
        return []

    out = []
    lower_context = (normalize_text(context) + " " + s).lower()

    for pattern, secret_type in SECRET_PATTERNS:
        for m in pattern.finditer(s):
            full = m.group(0)
            value = full
            if m.groups() and len(m.groups()) >= 2 and m.group(2):
                value = m.group(2)

            fp = sha256_hex(value)[:16]
            line_no = s.count("\n", 0, m.start()) + 1
            nearby = s[max(0, m.start() - 120): min(len(s), m.end() + 120)].lower()
            hint_blob = lower_context + " " + nearby

            state = "EXPOSED_SECRET_CANDIDATE"
            for hint in TEST_SECRET_HINTS:
                if hint in hint_blob:
                    state = "TEST_OR_EXAMPLE_CANDIDATE"
                    break

            out.append({
                "exposure_id": stable_id("SEC", location, secret_type, fp, line_no),
                "location": location,
                "line": line_no,
                "secret_type": secret_type,
                "state": state,
                "fingerprint": fp,
                "redacted_value": redact_secret_match(full),
                "raw_value_stored": False,
                "validated": False,
                "limitations": [
                    "Secret was not tested or validated.",
                    "Candidate may be false positive, example, test, expired, rotated, or revoked.",
                    "Raw secret value is intentionally not stored.",
                ],
            })

    return unique_preserve(out)


# --------------------------------------------------------------------
# Commits / contributors / roles
# --------------------------------------------------------------------

def normalize_signature_state(value: Any) -> str:
    s = normalize_text(value).upper()
    if s in {"VALID", "INVALID", "UNVERIFIED", "UNSIGNED", "UNKNOWN"}:
        return s
    if s in {"VERIFIED", "SIGNED"}:
        return "VALID"
    if s in {"BAD", "BROKEN"}:
        return "INVALID"
    return "UNKNOWN"


def add_contributor(
    contributors: Dict[str, Dict[str, Any]],
    contributor_id: str,
    role: str,
    account_id: Optional[str] = None,
    repository_id: Optional[str] = None,
    source_ids: Optional[List[str]] = None,
    timestamp: Optional[datetime] = None,
    display_name: Optional[str] = None,
) -> None:
    cid = normalize_text(contributor_id)
    if not cid:
        return
    if cid not in contributors:
        contributors[cid] = {
            "contributor_id": cid,
            "account_id": normalize_text(account_id) or None,
            "display_name": normalize_text(display_name) or None,
            "roles": set(),
            "repositories": set(),
            "commit_count": 0,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "source_ids": set(),
            "limitations": [
                "Contributor does not automatically mean employee, maintainer, code owner, or verified real person.",
            ],
        }
    c = contributors[cid]
    c["roles"].add(normalize_text(role).upper())
    if repository_id:
        c["repositories"].add(normalize_text(repository_id))
    for sid in source_ids or []:
        c["source_ids"].add(normalize_text(sid))
    if timestamp:
        if c["first_seen"] is None or timestamp < c["first_seen"]:
            c["first_seen"] = timestamp
        if c["last_seen"] is None or timestamp > c["last_seen"]:
            c["last_seen"] = timestamp
    if display_name and not c.get("display_name"):
        c["display_name"] = normalize_text(display_name)


def ingest_commits(
    manifest: Dict[str, Any],
    repos: Dict[str, Dict[str, Any]],
    accounts: Dict[str, Dict[str, Any]],
    privacy_cfg: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    commits: List[Dict[str, Any]] = []
    contributors: Dict[str, Dict[str, Any]] = {}
    secret_exposures: List[Dict[str, Any]] = []

    for idx, c in enumerate(manifest.get("commits", []) or []):
        repo_id = normalize_text(c.get("repository_id"))
        if repo_id:
            ensure_repository(repos, repo_id, "commit referenced missing repository")
        commit_hash = normalize_text(c.get("hash") or c.get("sha") or c.get("commit_id")).lower()
        commit_id = normalize_text(c.get("commit_id")) or stable_id("COMMIT", repo_id, commit_hash or idx)
        message = normalize_text(c.get("message"))
        loc = f"commit:{commit_id}"
        secrets = scan_secrets(message, loc, context="commit message")
        secret_exposures.extend(secrets)
        redacted_message = message
        for sec in secrets:
            redacted_message = redacted_message.replace(sec["redacted_value"], "[REDACTED_SECRET_CANDIDATE]")

        author = c.get("author") or {}
        committer = c.get("committer") or {}
        author_email = normalize_text(author.get("email"))
        committer_email = normalize_text(committer.get("email"))
        author_email_fp = sha256_hex(author_email)[:16] if author_email else None
        committer_email_fp = sha256_hex(committer_email)[:16] if committer_email else None

        author_account = normalize_text(author.get("account_id")) or None
        committer_account = normalize_text(committer.get("account_id")) or None
        if author_account:
            ensure_account(accounts, author_account, reason="commit author account reference")
        if committer_account:
            ensure_account(accounts, committer_account, reason="commit committer account reference")

        author_timestamp = parse_time(author.get("timestamp") or c.get("author_timestamp"))
        commit_timestamp = parse_time(committer.get("timestamp") or c.get("commit_timestamp") or c.get("timestamp"))
        source_ids = [normalize_text(x) for x in c.get("source_ids", []) or [] if normalize_text(x)]

        contributor_id = author_account or stable_id("CONTRIB", normalize_text(author.get("name")), author_email_fp or "")
        add_contributor(
            contributors,
            contributor_id,
            "CONTRIBUTOR",
            account_id=author_account,
            repository_id=repo_id,
            source_ids=source_ids,
            timestamp=author_timestamp or commit_timestamp,
            display_name=normalize_text(author.get("name")),
        )
        contributors[contributor_id]["commit_count"] += 1

        commits.append({
            "commit_id": commit_id,
            "repository_id": repo_id or None,
            "hash": commit_hash or None,
            "parents": [normalize_text(p).lower() for p in c.get("parents", []) or [] if normalize_text(p)],
            "author_identity": {
                "name": normalize_text(author.get("name")) or None,
                "email_fingerprint": author_email_fp,
                "email_display": mask_value(author_email) if author_email and privacy_cfg.get("mask_emails") else author_email or None,
                "account_id": author_account,
                "verified_real_person": False,
            },
            "author_timestamp": author_timestamp,
            "committer_identity": {
                "name": normalize_text(committer.get("name")) or None,
                "email_fingerprint": committer_email_fp,
                "email_display": mask_value(committer_email) if committer_email and privacy_cfg.get("mask_emails") else committer_email or None,
                "account_id": committer_account,
                "verified_real_person": False,
            },
            "commit_timestamp": commit_timestamp,
            "message_redacted": collapse_ws(redacted_message) if redacted_message else None,
            "signature_state": normalize_signature_state(c.get("signature_state")),
            "changed_files": [normalize_text(x) for x in c.get("changed_files", []) or [] if normalize_text(x)],
            "additions": int(c.get("additions", 0) or 0),
            "deletions": int(c.get("deletions", 0) or 0),
            "branch_context": normalize_text(c.get("branch_context")) or None,
            "source_ids": source_ids,
            "evidence_ids": [normalize_text(x) for x in c.get("evidence_ids", []) or [] if normalize_text(x)],
            "secret_exposure_ids": [s["exposure_id"] for s in secrets],
            "confidence_score": clamp(float(c.get("confidence", 0.70))),
            "limitations": list(c.get("limitations", []) or []) + [
                "Commit author metadata is not verified real-person identity.",
                "Committer is not automatically code author.",
                "Commit presence does not prove merge, release, build, or deployment.",
            ],
        })

    return commits, contributors, secret_exposures


def ingest_roles(
    manifest: Dict[str, Any],
    repos: Dict[str, Dict[str, Any]],
    accounts: Dict[str, Dict[str, Any]],
    contributors: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    maintainers: List[Dict[str, Any]] = []
    codeowners: List[Dict[str, Any]] = []

    for idx, m in enumerate(manifest.get("maintainers", []) or []):
        repo_id = normalize_text(m.get("repository_id"))
        account_id = normalize_text(m.get("account_id") or m.get("login"))
        if not account_id:
            continue
        ensure_repository(repos, repo_id, "maintainer referenced missing repository") if repo_id else None
        ensure_account(accounts, account_id, reason="maintainer record")
        add_contributor(
            contributors,
            account_id,
            "MAINTAINER",
            account_id=account_id,
            repository_id=repo_id,
            source_ids=[normalize_text(x) for x in m.get("source_ids", []) or [] if normalize_text(x)],
            timestamp=parse_time(m.get("valid_from")),
        )
        maintainers.append({
            "maintainer_id": normalize_text(m.get("maintainer_id")) or stable_id("MAINT", repo_id, account_id, idx),
            "repository_id": repo_id or None,
            "account_id": account_id,
            "role": normalize_text(m.get("role", "MAINTAINER")).upper(),
            "valid_from": parse_time(m.get("valid_from")),
            "valid_to": parse_time(m.get("valid_to")),
            "source_ids": [normalize_text(x) for x in m.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Maintainer role does not prove legal ownership or employment.",
            ],
        })

    for idx, co in enumerate(manifest.get("codeowners", []) or []):
        repo_id = normalize_text(co.get("repository_id"))
        owner = normalize_text(co.get("owner") or co.get("account_id"))
        if not owner:
            continue
        ensure_repository(repos, repo_id, "codeowner referenced missing repository") if repo_id else None
        ensure_account(accounts, owner.lstrip("@"), reason="codeowner record")
        add_contributor(
            contributors,
            owner.lstrip("@"),
            "CODEOWNER",
            account_id=owner.lstrip("@"),
            repository_id=repo_id,
            source_ids=[normalize_text(x) for x in co.get("source_ids", []) or [] if normalize_text(x)],
        )
        codeowners.append({
            "codeowner_id": stable_id("CODEOWN", repo_id, owner, idx),
            "repository_id": repo_id or None,
            "path_pattern": normalize_text(co.get("path_pattern") or co.get("path")) or "*",
            "owner": owner,
            "source_ids": [normalize_text(x) for x in co.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "CODEOWNERS indicates review responsibility, not legal ownership or employment.",
            ],
        })

    return maintainers, codeowners


# --------------------------------------------------------------------
# Branches / tags / releases / packages / dependencies / SBOM / advisories
# --------------------------------------------------------------------

def ingest_branches(manifest: Dict[str, Any], repos: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for idx, b in enumerate(manifest.get("branches", []) or []):
        repo_id = normalize_text(b.get("repository_id"))
        ensure_repository(repos, repo_id, "branch referenced missing repository") if repo_id else None
        out.append({
            "branch_id": stable_id("BRANCH", repo_id, b.get("branch_name"), idx),
            "repository_id": repo_id or None,
            "branch_name": normalize_text(b.get("branch_name") or b.get("name")),
            "head_commit": normalize_text(b.get("head_commit") or b.get("commit_id")).lower() or None,
            "default_state": bool(b.get("default", False)),
            "protected_state_if_authorized": normalize_text(b.get("protected_state")) or "UNKNOWN",
            "first_seen": parse_time(b.get("first_seen")),
            "last_seen": parse_time(b.get("last_seen")),
            "status": normalize_text(b.get("status", "UNKNOWN")).upper(),
            "source_ids": [normalize_text(x) for x in b.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Branch name does not automatically prove deployment environment.",
            ],
        })
    return out


def ingest_tags(manifest: Dict[str, Any], repos: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for idx, t in enumerate(manifest.get("tags", []) or []):
        repo_id = normalize_text(t.get("repository_id"))
        ensure_repository(repos, repo_id, "tag referenced missing repository") if repo_id else None
        out.append({
            "tag_id": stable_id("TAG", repo_id, t.get("tag"), idx),
            "repository_id": repo_id or None,
            "tag": normalize_text(t.get("tag") or t.get("name")),
            "target_commit": normalize_text(t.get("target_commit") or t.get("commit_id")).lower() or None,
            "annotated": bool(t.get("annotated", False)),
            "tagger_account": normalize_text(t.get("tagger_account") or t.get("tagger")) or None,
            "timestamp": parse_time(t.get("timestamp") or t.get("date")),
            "signature_state": normalize_signature_state(t.get("signature_state")),
            "source_ids": [normalize_text(x) for x in t.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Tag does not automatically equal platform release or deployed artifact.",
            ],
        })
    return out


def ingest_releases(manifest: Dict[str, Any], repos: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for idx, r in enumerate(manifest.get("releases", []) or []):
        repo_id = normalize_text(r.get("repository_id"))
        ensure_repository(repos, repo_id, "release referenced missing repository") if repo_id else None
        artifacts = []
        for a in r.get("artifacts", []) or []:
            artifacts.append({
                "artifact_id": stable_id("ART", repo_id, r.get("release_id"), a.get("name"), idx),
                "name": normalize_text(a.get("name")),
                "kind": normalize_text(a.get("kind", "UNKNOWN")).upper(),
                "url": normalize_text(a.get("url")) or None,
                "checksum": normalize_text(a.get("checksum")) or None,
                "checksum_algorithm": normalize_text(a.get("checksum_algorithm")) or "unknown",
                "signature": normalize_text(a.get("signature")) or None,
                "limitations": [
                    "Checksum proves integrity relative to published value, not safety.",
                    "Artifact was not executed or downloaded by REPOINT.",
                ],
            })
        out.append({
            "release_id": normalize_text(r.get("release_id")) or stable_id("REL", repo_id, r.get("tag") or r.get("name"), idx),
            "repository_id": repo_id or None,
            "tag": normalize_text(r.get("tag")) or None,
            "title": normalize_text(r.get("title") or r.get("name")) or None,
            "published_at": parse_time(r.get("published_at") or r.get("created_at")),
            "draft": bool(r.get("draft", False)),
            "prerelease": bool(r.get("prerelease", False)),
            "release_channel": normalize_text(r.get("release_channel", "UNKNOWN")).upper(),
            "artifacts": artifacts,
            "checksums": [normalize_text(x) for x in r.get("checksums", []) or [] if normalize_text(x)],
            "signature_metadata": r.get("signature_metadata") or {},
            "release_notes": normalize_text(r.get("release_notes")) or None,
            "published_by_account": normalize_text(r.get("published_by") or r.get("publisher_account")) or None,
            "source_ids": [normalize_text(x) for x in r.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Release does not automatically prove stable, deployed, or installed status.",
            ],
        })
    return out


def ingest_packages(manifest: Dict[str, Any], repos: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for idx, p in enumerate(manifest.get("packages", []) or []):
        repo_id = normalize_text(p.get("repository_id"))
        ecosystem = normalize_text(p.get("ecosystem", "unknown")).lower()
        name = normalize_text(p.get("package_name") or p.get("name"))
        version = normalize_text(p.get("version")) or None
        package_id = normalize_text(p.get("package_id")) or stable_id("PKG", ecosystem, name, version or "")
        relationship = normalize_text(p.get("repository_relationship", "UNKNOWN")).upper()
        out.append({
            "package_id": package_id,
            "ecosystem": ecosystem,
            "package_name": name,
            "version": version,
            "purl": normalize_text(p.get("purl")) or None,
            "source_registry": normalize_text(p.get("source_registry") or p.get("registry")) or None,
            "repository_id": repo_id or None,
            "repository_relationship": relationship,
            "publisher_account": normalize_text(p.get("publisher_account")) or None,
            "published_at": parse_time(p.get("published_at")),
            "source_ids": [normalize_text(x) for x in p.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Package is not repository.",
                "Package publisher is not automatically repository owner or real person.",
            ],
        })
    return out


def add_dependency(
    deps: List[Dict[str, Any]],
    consumer_type: str,
    consumer_id: str,
    dependency_name: str,
    ecosystem: str = "unknown",
    version_constraint: Optional[str] = None,
    resolved_version: Optional[str] = None,
    dependency_type: str = "UNKNOWN",
    directness: str = "UNKNOWN",
    depth: int = 1,
    source_ids: Optional[List[str]] = None,
    limitations: Optional[List[str]] = None,
) -> None:
    dep_id = stable_id("DEP", consumer_type, consumer_id, ecosystem, dependency_name, version_constraint or "", resolved_version or "")
    deps.append({
        "dependency_id": dep_id,
        "consumer_type": normalize_text(consumer_type).upper(),
        "consumer_id": normalize_text(consumer_id),
        "dependency_name": normalize_text(dependency_name),
        "ecosystem": normalize_text(ecosystem).lower(),
        "version_constraint": normalize_text(version_constraint) or None,
        "resolved_version": normalize_text(resolved_version) or None,
        "dependency_type": normalize_text(dependency_type).upper(),
        "directness": normalize_text(directness).upper(),
        "dependency_depth": int(depth),
        "source_ids": list(dict.fromkeys([normalize_text(x) for x in source_ids or [] if normalize_text(x)])),
        "limitations": list(limitations or []) + [
            "Dependency presence does not prove runtime reachability or deployment.",
        ],
    })


def ingest_dependencies(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    deps: List[Dict[str, Any]] = []
    for d in manifest.get("dependencies", []) or []:
        add_dependency(
            deps,
            d.get("consumer_type", "REPOSITORY"),
            d.get("consumer_id", ""),
            d.get("dependency_name", ""),
            d.get("ecosystem", "unknown"),
            d.get("version_constraint"),
            d.get("resolved_version"),
            d.get("dependency_type", "UNKNOWN"),
            d.get("directness", "DIRECT"),
            d.get("dependency_depth", 1),
            d.get("source_ids", []),
            d.get("limitations", []),
        )
    return deps


def ingest_sboms(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, s in enumerate(manifest.get("sboms", []) or []):
        out.append({
            "sbom_id": normalize_text(s.get("sbom_id")) or stable_id("SBOM", idx, s.get("repository_id"), s.get("format")),
            "repository_id": normalize_text(s.get("repository_id")) or None,
            "package_id": normalize_text(s.get("package_id")) or None,
            "format": normalize_text(s.get("format", "unknown")).lower(),
            "generated_at": parse_time(s.get("generated_at")),
            "components": s.get("components", []) or [],
            "dependency_edges": s.get("dependency_edges", []) or [],
            "source_ids": [normalize_text(x) for x in s.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": list(s.get("limitations", []) or []) + [
                "SBOM may be stale, incomplete, build-specific, or incorrectly generated.",
            ],
        })
    return out


def ingest_advisories(manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for idx, a in enumerate(manifest.get("security_advisories", []) or []):
        out.append({
            "advisory_id": normalize_text(a.get("advisory_id")) or stable_id("ADV", idx, a.get("cve"), a.get("ghsa")),
            "repository_id": normalize_text(a.get("repository_id")) or None,
            "package_id": normalize_text(a.get("package_id")) or None,
            "package_name": normalize_text(a.get("package_name")) or None,
            "cve": normalize_text(a.get("cve")) or None,
            "ghsa": normalize_text(a.get("ghsa")) or None,
            "gitlab_advisory": normalize_text(a.get("gitlab_advisory")) or None,
            "affected_versions": normalize_text(a.get("affected_versions")) or None,
            "fixed_versions": normalize_text(a.get("fixed_versions")) or None,
            "published_at": parse_time(a.get("published_at")),
            "updated_at": parse_time(a.get("updated_at")),
            "status": normalize_text(a.get("status", "UNKNOWN")).upper(),
            "source_ids": [normalize_text(x) for x in a.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Advisory does not prove exploitation, deployment, or applicability without VULNINT analysis.",
            ],
        })
    return out


def ingest_repository_relationships(manifest: Dict[str, Any], repos: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    allowed = {
        "FORKED_FROM",
        "MIRRORED_FROM",
        "DERIVED_FROM",
        "MIGRATED_FROM",
        "SUCCESSOR_OF",
        "SPLIT_FROM",
        "MERGED_INTO",
        "TRANSFERRED_FROM",
        "TRANSFERRED_TO",
    }
    for idx, r in enumerate(manifest.get("repository_relationships", []) or []):
        source = normalize_text(r.get("source_repository") or r.get("from"))
        target = normalize_text(r.get("target_repository") or r.get("to"))
        rel_type = normalize_text(r.get("relationship_type") or r.get("type")).upper()
        if not source or not target:
            continue
        ensure_repository(repos, source, "relationship referenced missing source repository")
        ensure_repository(repos, target, "relationship referenced missing target repository")
        out.append({
            "relationship_id": normalize_text(r.get("relationship_id")) or stable_id("REPOREL", source, target, rel_type, idx),
            "source_repository": source,
            "target_repository": target,
            "relationship_type": rel_type if rel_type in allowed else "UNKNOWN",
            "valid_from": parse_time(r.get("valid_from")),
            "valid_to": parse_time(r.get("valid_to")),
            "evidence": normalize_text(r.get("evidence")) or None,
            "source_ids": [normalize_text(x) for x in r.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Fork/mirror relationship does not automatically establish canonicality or independent authorship.",
            ],
        })
    return out


def ingest_control_eras(manifest: Dict[str, Any], repos: Dict[str, Dict[str, Any]], accounts: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for idx, e in enumerate(manifest.get("control_eras", []) or []):
        repo_id = normalize_text(e.get("repository_id"))
        owner = normalize_text(e.get("owner_account"))
        ensure_repository(repos, repo_id, "control era referenced missing repository") if repo_id else None
        if owner:
            ensure_account(accounts, owner, reason="control era owner")
        out.append({
            "era_id": normalize_text(e.get("era_id")) or stable_id("ERA", repo_id, owner, idx),
            "repository_id": repo_id or None,
            "owner_account": owner or None,
            "maintainers": [normalize_text(x) for x in e.get("maintainers", []) or [] if normalize_text(x)],
            "platform": normalize_text(e.get("platform")) or None,
            "valid_from": parse_time(e.get("valid_from")),
            "valid_to": parse_time(e.get("valid_to")),
            "evidence": normalize_text(e.get("evidence")) or None,
            "source_ids": [normalize_text(x) for x in e.get("source_ids", []) or [] if normalize_text(x)],
            "limitations": [
                "Control era describes hosting/control context, not necessarily legal IP ownership.",
            ],
        })
    return out


# --------------------------------------------------------------------
# File parsing: manifests, lockfiles, SBOMs, CI, LICENSE, CODEOWNERS
# --------------------------------------------------------------------

def detect_license_identifier(content: str) -> Optional[str]:
    low = normalize_text(content).lower()
    if not low:
        return None
    for ident, hints in LICENSE_SIGNATURES:
        if all(h in low for h in hints):
            return ident
    return None


def detect_deprecation(content: str) -> bool:
    low = normalize_text(content).lower()
    return any(h in low for h in DEPRECATION_HINTS)


def parse_package_json(content: str, repo_id: str, source_ids: List[str]) -> Tuple[List[Dict[str, Any]], Optional[str], List[str]]:
    deps = []
    package_name = None
    limitations = []
    try:
        data = json.loads(content)
    except Exception as exc:
        return deps, package_name, [f"package.json parse failed: {exc}"]

    package_name = normalize_text(data.get("name")) or None
    sections = {
        "dependencies": "RUNTIME",
        "devDependencies": "DEVELOPMENT",
        "peerDependencies": "PEER",
        "optionalDependencies": "OPTIONAL",
    }
    for section, dtype in sections.items():
        for name, constraint in (data.get(section) or {}).items():
            add_dependency(
                deps,
                "REPOSITORY",
                repo_id,
                name,
                "npm",
                constraint if isinstance(constraint, str) else json_safe(constraint),
                None,
                dtype,
                "DIRECT",
                1,
                source_ids,
                ["Manifest version range is not resolved/deployed version."],
            )
    return deps, package_name, limitations


def parse_requirements_txt(content: str, repo_id: str, source_ids: List[str]) -> Tuple[List[Dict[str, Any]], List[str]]:
    deps = []
    limitations = []
    for line in content.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(.*)$", s)
        if not m:
            continue
        name = m.group(1)
        constraint = m.group(2).strip()
        add_dependency(
            deps,
            "REPOSITORY",
            repo_id,
            name,
            "pypi",
            constraint or None,
            None,
            "RUNTIME",
            "DIRECT",
            1,
            source_ids,
            ["requirements.txt may not represent resolved deployment."],
        )
    return deps, limitations


def parse_cyclonedx(content: str, repo_id: str, source_ids: List[str]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    limitations = []
    try:
        data = json.loads(content)
    except Exception as exc:
        return None, [], [f"CycloneDX parse failed: {exc}"]

    if normalize_text(data.get("bomFormat")) != "CycloneDX" and "components" not in data:
        return None, [], ["File did not appear to be CycloneDX."]

    components = []
    deps = []
    for comp in data.get("components", []) or []:
        components.append({
            "name": normalize_text(comp.get("name")),
            "version": normalize_text(comp.get("version")) or None,
            "purl": normalize_text(comp.get("purl")) or None,
            "type": normalize_text(comp.get("type")) or None,
            "licenses": comp.get("licenses", []) or [],
            "hashes": comp.get("hashes", []) or [],
            "supplier": comp.get("supplier"),
        })

    # Very light dependency edge capture.
    for dep in data.get("dependencies", []) or []:
        ref = normalize_text(dep.get("ref"))
        depends_on = [normalize_text(x) for x in dep.get("dependsOn", []) or [] if normalize_text(x)]
        if ref and depends_on:
            for d in depends_on:
                add_dependency(
                    deps,
                    "SBOM",
                    ref,
                    d,
                    "unknown",
                    None,
                    None,
                    "UNKNOWN",
                    "TRANSITIVE",
                    2,
                    source_ids,
                    ["SBOM dependency edge may be build-specific or stale."],
                )

    sbom = {
        "sbom_id": stable_id("SBOM_FILE", repo_id, "cyclonedx"),
        "repository_id": repo_id,
        "format": "cyclonedx",
        "generated_at": parse_time(data.get("metadata", {}).get("timestamp")),
        "components": components,
        "dependency_edges": data.get("dependencies", []) or [],
        "source_ids": source_ids,
        "limitations": [
            "SBOM is not automatically deployed reality.",
        ],
    }
    return sbom, deps, limitations


def parse_spdx(content: str, repo_id: str, source_ids: List[str]) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    limitations = []
    try:
        data = json.loads(content)
    except Exception as exc:
        return None, [f"SPDX parse failed: {exc}"]

    if "spdxVersion" not in data and "packages" not in data:
        return None, ["File did not appear to be SPDX JSON."]

    components = []
    for pkg in data.get("packages", []) or []:
        components.append({
            "name": normalize_text(pkg.get("name")),
            "version": normalize_text(pkg.get("versionInfo")) or None,
            "purl": None,
            "type": normalize_text(pkg.get("primaryPackagePurpose")) or None,
            "licenses": pkg.get("licenseDeclared") or pkg.get("licenseConcluded"),
            "hashes": pkg.get("checksums", []) or [],
            "supplier": pkg.get("supplier"),
        })

    sbom = {
        "sbom_id": stable_id("SBOM_FILE", repo_id, "spdx"),
        "repository_id": repo_id,
        "format": "spdx",
        "generated_at": parse_time((data.get("creationInfo") or {}).get("created")),
        "components": components,
        "dependency_edges": data.get("relationships", []) or [],
        "source_ids": source_ids,
        "limitations": ["SPDX document may be incomplete or build-specific."],
    }
    return sbom, limitations


def parse_codeowners(content: str, repo_id: str, source_ids: List[str]) -> List[Dict[str, Any]]:
    out = []
    for idx, line in enumerate(content.splitlines()):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if not parts:
            continue
        path_pattern = parts[0]
        owners = [p for p in parts[1:] if p.startswith("@")]
        for owner in owners:
            out.append({
                "codeowner_id": stable_id("CODEOWN_FILE", repo_id, path_pattern, owner, idx),
                "repository_id": repo_id,
                "path_pattern": path_pattern,
                "owner": owner,
                "source_ids": source_ids,
                "limitations": [
                    "CODEOWNERS file indicates review responsibility, not legal ownership or employment.",
                ],
            })
    return out


def parse_github_workflow(content: str, repo_id: str, path: str, source_ids: List[str]) -> Dict[str, Any]:
    triggers = []
    for token in ("push", "pull_request", "schedule", "workflow_dispatch", "release", "workflow_call"):
        if re.search(rf"(?mi)^\s*{re.escape(token)}\s*:", content) or re.search(rf"(?mi)^\s*{re.escape(token)}\s*$", content):
            triggers.append(token)

    uses = re.findall(r"(?mi)^\s*uses:\s*([^\s#]+)", content)
    third_party_actions = []
    local_actions = []
    for u in uses:
        u = normalize_text(u)
        if u.startswith("./"):
            local_actions.append(u)
            continue
        m = re.match(r"^([^@]+)@(.+)$", u)
        if not m:
            continue
        action = m.group(1)
        ref = m.group(2)
        pinned = bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))
        third_party_actions.append({
            "action": action,
            "ref": ref,
            "pinned_to_commit": pinned,
            "floating_reference": not pinned,
            "limitations": [
                "Floating action references may reduce reproducibility; defensive signal only, not exploit guidance.",
            ],
        })

    secret_refs = re.findall(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}", content)
    permissions = re.findall(
        r"(?mi)^\s*(contents|actions|checks|deployments|issues|packages|pull-requests|repository-projects|security-events|statuses)\s*:\s*(read|write|none)",
        content,
    )
    env_refs = re.findall(r"\$\{\{\s*env\.([A-Za-z0-9_]+)\s*\}\}", content)

    return {
        "workflow_id": stable_id("WF", repo_id, path),
        "repository_id": repo_id,
        "platform": "github_actions",
        "path": path,
        "triggers": list(dict.fromkeys(triggers)),
        "third_party_actions": third_party_actions,
        "local_actions": local_actions,
        "secret_references": list(dict.fromkeys(secret_refs)),
        "environment_references": list(dict.fromkeys(env_refs)),
        "permissions": [{"scope": k, "level": v} for k, v in permissions],
        "source_ids": source_ids,
        "limitations": [
            "Workflow file presence does not prove active pipeline.",
            "Secret reference name is not secret value.",
            "No workflow was triggered or executed.",
        ],
    }


def parse_gitlab_ci(content: str, repo_id: str, path: str, source_ids: List[str]) -> Dict[str, Any]:
    images = re.findall(r"(?mi)^\s*image:\s*([^\s#]+)", content)
    services = re.findall(r"(?mi)^\s*-\s*([a-z0-9./:_-]+)", content)
    variables = re.findall(r"(?mi)^\s*([A-Z0-9_]+):", content)
    return {
        "workflow_id": stable_id("WF", repo_id, path),
        "repository_id": repo_id,
        "platform": "gitlab_ci",
        "path": path,
        "triggers": [],
        "third_party_actions": [],
        "local_actions": [],
        "container_images": list(dict.fromkeys(images)),
        "services": list(dict.fromkeys(services))[:100],
        "variable_names": list(dict.fromkeys(variables))[:200],
        "secret_references": [],
        "permissions": [],
        "source_ids": source_ids,
        "limitations": [
            "CI file presence does not prove active pipeline.",
            "Variable names are not secret values.",
        ],
    }


def ingest_repository_files(
    manifest: Dict[str, Any],
    repos: Dict[str, Dict[str, Any]],
    accounts: Dict[str, Dict[str, Any]],
    contributors: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    artifacts: Dict[str, Any] = {
        "dependencies": [],
        "sboms": [],
        "workflows": [],
        "codeowners": [],
        "licenses": {},
        "deprecation": {},
        "secret_exposures": [],
        "file_inventory": [],
        "limitations": [],
    }

    for idx, f in enumerate(manifest.get("repository_files", []) or []):
        repo_id = normalize_text(f.get("repository_id"))
        path = normalize_text(f.get("path"))
        content = normalize_text(f.get("content"))
        if not repo_id or not path:
            continue
        ensure_repository(repos, repo_id, "file referenced missing repository")
        source_ids = [normalize_text(x) for x in f.get("source_ids", []) or [] if normalize_text(x)]
        content_hash = sha256_hex(content) if content else None
        size = len(content.encode("utf-8")) if content else 0

        artifacts["file_inventory"].append({
            "file_id": stable_id("FILE", repo_id, path, idx),
            "repository_id": repo_id,
            "path": path,
            "sha256": content_hash,
            "size_bytes": size,
            "source_ids": source_ids,
            "executed": False,
            "limitations": ["File content was parsed statically only; not executed."],
        })

        if content:
            secrets = scan_secrets(content, f"file:{repo_id}:{path}", context=path)
            artifacts["secret_exposures"].extend(secrets)

        base = Path(path).name.lower()
        lower_path = path.lower()

        if base in {"license", "license.txt", "license.md", "copying", "copying.txt"}:
            lic = detect_license_identifier(content)
            if lic:
                artifacts["licenses"][repo_id] = {
                    "license_identifier": lic,
                    "source": path,
                    "source_ids": source_ids,
                    "limitations": ["License detection is heuristic; legal interpretation requires LEGALINT."],
                }

        if base == "readme.md" or base.startswith("readme"):
            if detect_deprecation(content):
                artifacts["deprecation"][repo_id] = {
                    "state": "DEPRECATION_CANDIDATE",
                    "source": path,
                    "source_ids": source_ids,
                }

        if base == "codeowners" or lower_path.endswith("/codeowners"):
            artifacts["codeowners"].extend(parse_codeowners(content, repo_id, source_ids))
            for co in artifacts["codeowners"][-100:]:
                owner = normalize_text(co.get("owner", "")).lstrip("@")
                if owner:
                    ensure_account(accounts, owner, reason="CODEOWNERS owner reference")
                    add_contributor(contributors, owner, "CODEOWNER", account_id=owner, repository_id=repo_id, source_ids=source_ids)

        if base == "package.json":
            deps, pkg_name, lims = parse_package_json(content, repo_id, source_ids)
            artifacts["dependencies"].extend(deps)
            artifacts["limitations"].extend(lims)

        if base == "requirements.txt":
            deps, lims = parse_requirements_txt(content, repo_id, source_ids)
            artifacts["dependencies"].extend(deps)
            artifacts["limitations"].extend(lims)

        if lower_path.endswith(".cdx.json") or '"bomformat"' in content.lower().replace(" ", ""):
            sbom, deps, lims = parse_cyclonedx(content, repo_id, source_ids)
            if sbom:
                artifacts["sboms"].append(sbom)
                artifacts["dependencies"].extend(deps)
            artifacts["limitations"].extend(lims)

        if lower_path.endswith(".spdx.json") or '"spdxversion"' in content.lower().replace(" ", ""):
            sbom, lims = parse_spdx(content, repo_id, source_ids)
            if sbom:
                artifacts["sboms"].append(sbom)
            artifacts["limitations"].extend(lims)

        if lower_path.startswith(".github/workflows/") and (lower_path.endswith(".yml") or lower_path.endswith(".yaml")):
            artifacts["workflows"].append(parse_github_workflow(content, repo_id, path, source_ids))

        if base == ".gitlab-ci.yml":
            artifacts["workflows"].append(parse_gitlab_ci(content, repo_id, path, source_ids))

    return artifacts


# --------------------------------------------------------------------
# Analysis / enrichment
# --------------------------------------------------------------------

def group_by_repo(items: List[Dict[str, Any]], key: str = "repository_id") -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in items:
        rid = normalize_text(item.get(key))
        if rid:
            out[rid].append(item)
    return dict(out)


def compute_repo_source_independence(
    repo_id: str,
    repos: Dict[str, Dict[str, Any]],
    commits: List[Dict[str, Any]],
    releases: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    sources: Dict[str, Dict[str, Any]],
    source_roots: Dict[str, str],
) -> Dict[str, Any]:
    source_ids = set(repos.get(repo_id, {}).get("source_ids", []) or [])
    for c in commits:
        if c.get("repository_id") == repo_id:
            source_ids.update(c.get("source_ids", []) or [])
    for r in releases:
        if r.get("repository_id") == repo_id:
            source_ids.update(r.get("source_ids", []) or [])
    for rel in relationships:
        if rel.get("source_repository") == repo_id or rel.get("target_repository") == repo_id:
            source_ids.update(rel.get("source_ids", []) or [])

    source_ids = sorted(source_ids)
    families = source_family_ids(source_ids, source_roots)
    max_rel, avg_rel = source_quality(source_ids, sources)
    return {
        "source_ids": source_ids,
        "raw_source_count": len(source_ids),
        "independent_source_family_count": len(families),
        "source_independence_state": independence_state(families, sources, source_ids),
        "source_max_reliability": round(max_rel, 4),
        "source_avg_reliability": round(avg_rel, 4),
    }


def compute_project_health(
    repo: Dict[str, Any],
    commits: List[Dict[str, Any]],
    releases: List[Dict[str, Any]],
    maintainers: List[Dict[str, Any]],
    deprecation_info: Dict[str, Any],
    as_of: datetime,
) -> Dict[str, Any]:
    repo_id = repo["repository_id"]
    repo_commits = [c for c in commits if c.get("repository_id") == repo_id]
    repo_releases = [r for r in releases if r.get("repository_id") == repo_id]
    repo_maintainers = [m for m in maintainers if m.get("repository_id") == repo_id]

    commit_times = [c.get("commit_timestamp") or c.get("author_timestamp") for c in repo_commits]
    commit_times = [t for t in commit_times if t]
    release_times = [r.get("published_at") for r in repo_releases if r.get("published_at")]

    latest_commit = max(commit_times) if commit_times else None
    latest_release = max(release_times) if release_times else None
    days_since_commit = (as_of - latest_commit).days if latest_commit else None
    days_since_release = (as_of - latest_release).days if latest_release else None

    active_maintainers = [
        m for m in repo_maintainers
        if (m.get("valid_to") is None or m["valid_to"] >= as_of)
        and (m.get("valid_from") is None or m["valid_from"] <= as_of)
    ]

    archived = bool(repo.get("archived"))
    deprecated = bool(deprecation_info.get(repo_id))

    if archived:
        state = "ARCHIVED"
    elif deprecated:
        state = "DEPRECATED"
    elif days_since_commit is None:
        state = "UNKNOWN"
    elif days_since_commit <= 90:
        state = "ACTIVE"
    elif days_since_commit <= 365:
        state = "LOW_ACTIVITY"
    elif days_since_commit > 730 and len(active_maintainers) <= 1:
        state = "ABANDONMENT_CANDIDATE"
    else:
        state = "MAINTENANCE_MODE"

    return {
        "repository_id": repo_id,
        "health_state": state,
        "archived": archived,
        "deprecation_candidate": deprecated,
        "latest_commit": latest_commit,
        "latest_release": latest_release,
        "days_since_commit": days_since_commit,
        "days_since_release": days_since_release,
        "commit_count": len(repo_commits),
        "release_count": len(repo_releases),
        "maintainer_count": len(active_maintainers),
        "bus_factor_candidate": len(active_maintainers) <= 1,
        "limitations": [
            "Project health is not security verdict.",
            "Low activity is not automatically abandonment.",
            "Archived repository may still be deployed or security-relevant.",
        ],
    }


def detect_contradictions(
    repos: Dict[str, Dict[str, Any]],
    commits: List[Dict[str, Any]],
    tags: List[Dict[str, Any]],
    releases: List[Dict[str, Any]],
    packages: List[Dict[str, Any]],
    maintainers: List[Dict[str, Any]],
    accounts: Dict[str, Dict[str, Any]],
    licenses_detected: Dict[str, Dict[str, Any]],
    relationships: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    contradictions = []
    tags_by_repo = defaultdict(set)
    for t in tags:
        if t.get("repository_id") and t.get("tag"):
            tags_by_repo[t["repository_id"]].add(t["tag"])

    commits_by_repo = defaultdict(list)
    for c in commits:
        if c.get("repository_id"):
            commits_by_repo[c["repository_id"]].append(c)

    for repo_id, repo in repos.items():
        if repo.get("fork_state") == "CANONICAL" and repo.get("upstream_repository"):
            contradictions.append({
                "contradiction_id": stable_id("CTR", "canonical_upstream", repo_id),
                "type": "CANONICAL_WITH_UPSTREAM_CONTRADICTION",
                "severity": "MATERIAL",
                "repository_id": repo_id,
                "detail": "Repository marked canonical but also has upstream repository reference.",
                "possible_causes": ["stale metadata", "fork promoted incorrectly", "mirror mislabelled", "migration"],
            })

        if repo.get("mirror_state") == "MIRROR" and repo.get("fork_state") == "CANONICAL":
            contradictions.append({
                "contradiction_id": stable_id("CTR", "mirror_canonical", repo_id),
                "type": "MIRROR_CANONICAL_CONFLICT",
                "severity": "MATERIAL",
                "repository_id": repo_id,
                "detail": "Repository marked both mirror and canonical.",
                "possible_causes": ["metadata error", "upstream/downstream confusion"],
            })

        archived_at = repo.get("archived_at")
        if repo.get("archived") and archived_at:
            later = [c for c in commits_by_repo.get(repo_id, []) if (c.get("commit_timestamp") or c.get("author_timestamp")) and (c.get("commit_timestamp") or c.get("author_timestamp")) > archived_at]
            if later:
                contradictions.append({
                    "contradiction_id": stable_id("CTR", "archived_later_commit", repo_id),
                    "type": "ARCHIVED_WITH_LATER_COMMIT",
                    "severity": "MATERIAL",
                    "repository_id": repo_id,
                    "detail": "Repository marked archived but provided commit history includes later commits.",
                    "possible_causes": ["archival date wrong", "history rewrite", "mirror/fork confusion", "metadata lag"],
                })

        repo_license = normalize_text(repo.get("license")).lower()
        detected = licenses_detected.get(repo_id, {}).get("license_identifier")
        if repo_license and detected and repo_license != detected.lower() and repo_license not in {"unknown", "none"}:
            contradictions.append({
                "contradiction_id": stable_id("CTR", "license", repo_id),
                "type": "LICENSE_CONFLICT",
                "severity": "MATERIAL",
                "repository_id": repo_id,
                "detail": f"Repository metadata license '{repo_license}' conflicts with detected LICENSE '{detected}'.",
                "possible_causes": ["dual licensing", "stale metadata", "vendored code", "license file change"],
                "handoff": "LEGALINT",
            })

    for rel in relationships:
        if rel.get("relationship_type") == "FORKED_FROM":
            source_repo = repos.get(rel.get("source_repository", ""), {})
            if source_repo.get("fork_state") not in {"FORK", "UNKNOWN"}:
                contradictions.append({
                    "contradiction_id": stable_id("CTR", "fork_state_rel", rel["relationship_id"]),
                    "type": "FORK_RELATIONSHIP_STATE_CONFLICT",
                    "severity": "LOW",
                    "relationship_id": rel["relationship_id"],
                    "detail": "FORKED_FROM relationship exists but source repository fork_state is not FORK.",
                })

    for r in releases:
        repo_id = r.get("repository_id")
        tag = r.get("tag")
        if repo_id and tag and tag not in tags_by_repo.get(repo_id, set()):
            contradictions.append({
                "contradiction_id": stable_id("CTR", "release_tag_missing", r["release_id"]),
                "type": "RELEASE_TAG_MISSING_IN_PROVIDED_TAGS",
                "severity": "LOW",
                "release_id": r["release_id"],
                "repository_id": repo_id,
                "detail": f"Release references tag '{tag}' not present in provided tag inventory.",
                "possible_causes": ["tag not ingested", "deleted tag", "release automation", "mirror lag"],
            })

    for m in maintainers:
        acc = accounts.get(m.get("account_id", ""), {})
        if normalize_text(acc.get("account_type")).upper() == "BOT" or "bot" in normalize_text(acc.get("login", "")).lower():
            contradictions.append({
                "contradiction_id": stable_id("CTR", "bot_maintainer", m["maintainer_id"]),
                "type": "BOT_MAINTAINER_CANDIDATE",
                "severity": "LOW",
                "maintainer_id": m["maintainer_id"],
                "detail": "Maintainer account appears bot/automation-associated.",
                "possible_causes": ["release bot", "dependency bot", "CI automation", "mislabelled account type"],
            })

    for p in packages:
        if p.get("repository_id") and p["repository_id"] not in repos:
            contradictions.append({
                "contradiction_id": stable_id("CTR", "package_repo_missing", p["package_id"]),
                "type": "PACKAGE_REPO_UNRESOLVED",
                "severity": "MATERIAL",
                "package_id": p["package_id"],
                "detail": "Package references repository not present in repository inventory.",
            })

    return contradictions


def generate_hypotheses(
    repos: Dict[str, Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    packages: List[Dict[str, Any]],
    secret_exposures: List[Dict[str, Any]],
    releases: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    hypotheses = []

    for repo_id, repo in repos.items():
        rels = [r for r in relationships if r.get("source_repository") == repo_id or r.get("target_repository") == repo_id]
        upstream = repo.get("upstream_repository")
        fork_state = repo.get("fork_state")
        mirror_state = repo.get("mirror_state")

        hypotheses.append({
            "hypothesis_id": stable_id("HYP", repo_id, "canonical"),
            "subject_type": "REPOSITORY",
            "subject_id": repo_id,
            "statement": f"Repository {repo_id} is canonical upstream for the project.",
            "support": [
                f"fork_state={fork_state}",
                f"mirror_state={mirror_state}",
                f"upstream_repository={upstream}",
                f"relationship_count={len(rels)}",
            ],
            "opposition": [
                "Upstream reference present" if upstream else None,
                "Fork state marked FORK" if fork_state == "FORK" else None,
                "Mirror state marked MIRROR" if mirror_state == "MIRROR" else None,
            ],
            "unknowns": ["Official project documentation confirmation", "Package registry source repository confirmation"],
            "falsification_conditions": [
                "Official project docs identify another canonical repository.",
                "Package registry links to different source repository.",
                "Repository is demonstrated to be mirror/fork only.",
            ],
            "status": "CANDIDATE" if fork_state == "UNKNOWN" else ("SUPPORTED" if fork_state == "CANONICAL" and not upstream else "DISPUTED"),
        })

        if fork_state == "FORK" or any(r.get("relationship_type") == "FORKED_FROM" and r.get("source_repository") == repo_id for r in rels):
            hypotheses.append({
                "hypothesis_id": stable_id("HYP", repo_id, "independent_fork"),
                "subject_type": "REPOSITORY",
                "subject_id": repo_id,
                "statement": f"Repository {repo_id} is an independent fork rather than canonical upstream.",
                "support": ["fork_state=FORK or FORKED_FROM relationship"],
                "opposition": ["May still closely track upstream"],
                "unknowns": ["Divergence commits", "Governance statement"],
                "falsification_conditions": ["Project declares this repo canonical", "Upstream is actually downstream mirror"],
                "status": "CANDIDATE",
            })

        if mirror_state == "MIRROR":
            hypotheses.append({
                "hypothesis_id": stable_id("HYP", repo_id, "mirror"),
                "subject_type": "REPOSITORY",
                "subject_id": repo_id,
                "statement": f"Repository {repo_id} is a mirror and not independent source origin.",
                "support": ["mirror_state=MIRROR"],
                "opposition": ["Mirror may have local patches"],
                "unknowns": ["Sync frequency", "divergence"],
                "falsification_conditions": ["Repository has independent commit authorship not present upstream"],
                "status": "CANDIDATE",
            })

    for p in packages:
        repo_id = p.get("repository_id")
        hypotheses.append({
            "hypothesis_id": stable_id("HYP", p["package_id"], "published_from_repo"),
            "subject_type": "PACKAGE",
            "subject_id": p["package_id"],
            "statement": f"Package {p.get('package_name')} {p.get('version') or ''} is published from repository {repo_id}.",
            "support": [f"repository_relationship={p.get('repository_relationship')}", f"registry={p.get('source_registry')}"],
            "opposition": ["Publisher account may differ from repo owner", "Release provenance not verified"],
            "unknowns": ["Build attestation", "tag/commit mapping", "artifact provenance"],
            "falsification_conditions": ["Registry source link points elsewhere", "Release artifact provenance maps to different repo/build"],
            "status": "CANDIDATE" if repo_id else "UNRESOLVED",
        })

    for s in secret_exposures:
        hypotheses.extend([
            {
                "hypothesis_id": stable_id("HYP", s["exposure_id"], "active"),
                "subject_type": "SECRET_EXPOSURE",
                "subject_id": s["exposure_id"],
                "statement": "Exposed secret candidate may still be active.",
                "support": [f"state={s['state']}", f"location={s['location']}"],
                "opposition": ["No validation performed", "May be example/test/expired"],
                "unknowns": ["Owner-side rotation/revocation evidence"],
                "falsification_conditions": ["Owner confirms rotation/revocation", "Pattern is false positive"],
                "status": "UNRESOLVED",
            },
            {
                "hypothesis_id": stable_id("HYP", s["exposure_id"], "test_example"),
                "subject_type": "SECRET_EXPOSURE",
                "subject_id": s["exposure_id"],
                "statement": "Secret candidate is test/example/placeholder.",
                "support": [f"state={s['state']}"],
                "opposition": ["Pattern resembles real credential format"],
                "unknowns": ["Context owner intent"],
                "falsification_conditions": ["Independent evidence shows credential was live"],
                "status": "CANDIDATE" if s["state"] == "TEST_OR_EXAMPLE_CANDIDATE" else "UNRESOLVED",
            },
            {
                "hypothesis_id": stable_id("HYP", s["exposure_id"], "rotated"),
                "subject_type": "SECRET_EXPOSURE",
                "subject_id": s["exposure_id"],
                "statement": "Secret was rotated/revoked after exposure.",
                "support": ["Remediation evidence not present in this starter"],
                "opposition": ["No owner-side evidence"],
                "unknowns": ["CREDINT remediation context"],
                "falsification_conditions": ["Service logs show use after exposure"],
                "status": "UNRESOLVED",
            },
        ])

    for r in releases:
        hypotheses.append({
            "hypothesis_id": stable_id("HYP", r["release_id"], "deployment"),
            "subject_type": "RELEASE",
            "subject_id": r["release_id"],
            "statement": f"Release {r.get('tag') or r['release_id']} may be deployed in production/target systems.",
            "support": ["Release published metadata present"],
            "opposition": ["No deployment evidence provided"],
            "unknowns": ["Installation telemetry", "runtime version", "environment inventory"],
            "falsification_conditions": ["Deployment records show different version", "Artifact never installed"],
            "status": "UNKNOWN",
        })

    return hypotheses[:1000]


def build_ach_stub(hypotheses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Lightweight ACH-style grouping by subject.
    by_subject: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for h in hypotheses:
        by_subject[(h.get("subject_type", "UNKNOWN"), h.get("subject_id", "UNKNOWN"))].append(h)

    out = []
    for (stype, sid), hs in list(by_subject.items())[:200]:
        out.append({
            "ach_id": stable_id("ACH", stype, sid),
            "subject_type": stype,
            "subject_id": sid,
            "hypotheses": [
                {
                    "hypothesis_id": h["hypothesis_id"],
                    "statement": h["statement"],
                    "status": h["status"],
                    "support": h.get("support", []),
                    "opposition": [x for x in h.get("opposition", []) if x],
                    "falsification_conditions": h.get("falsification_conditions", []),
                }
                for h in hs
            ],
            "limitations": [
                "ACH stub is analytical support only.",
                "No autonomous accusation, compromise verdict, or malicious intent claim is made.",
            ],
        })
    return out


def build_gaps(
    repos: Dict[str, Dict[str, Any]],
    packages: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
    sboms: List[Dict[str, Any]],
    workflows: List[Dict[str, Any]],
    advisories: List[Dict[str, Any]],
    secret_exposures: List[Dict[str, Any]],
    licenses_detected: Dict[str, Dict[str, Any]],
    health: Dict[str, Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    gaps = []

    for repo_id, repo in repos.items():
        if repo.get("fork_state") == "UNKNOWN" and not repo.get("upstream_repository"):
            gaps.append({
                "gap_id": stable_id("GAP", "canonical", repo_id),
                "type": "CANONICAL_REPOSITORY_UNRESOLVED",
                "importance": "HIGH",
                "repository_id": repo_id,
                "recommended_source": "Official project documentation, package registry source link, release provenance, or maintainer statement.",
                "specialist": "REPOINT / PACKAGEINT / DOCINT",
                "expected_information_value": "Distinguish canonical upstream from fork/mirror.",
            })

        if repo.get("owner_account") and not repo.get("legal_owner_evidence"):
            gaps.append({
                "gap_id": stable_id("GAP", "legal_owner", repo_id),
                "type": "LEGAL_OWNERSHIP_UNRESOLVED",
                "importance": "MEDIUM",
                "repository_id": repo_id,
                "recommended_source": "Corporate filings, official website, license/copyright headers, project governance docs.",
                "specialist": "CORPINT / LEGALINT",
                "expected_information_value": "Separate hosting account from legal IP ownership.",
            })

        if not repo.get("license") and repo_id not in licenses_detected:
            gaps.append({
                "gap_id": stable_id("GAP", "license", repo_id),
                "type": "LICENSE_UNRESOLVED",
                "importance": "MEDIUM",
                "repository_id": repo_id,
                "recommended_source": "LICENSE file, package metadata, official project docs.",
                "specialist": "REPOINT / LEGALINT",
                "expected_information_value": "Avoid assuming public domain or free use.",
            })

        h = health.get(repo_id, {})
        if h.get("health_state") in {"UNKNOWN", "ABANDONMENT_CANDIDATE"}:
            gaps.append({
                "gap_id": stable_id("GAP", "health", repo_id),
                "type": "PROJECT_HEALTH_UNRESOLVED",
                "importance": "MEDIUM",
                "repository_id": repo_id,
                "recommended_source": "Recent releases, maintainer statements, security advisory activity, support policy.",
                "specialist": "REPOINT / SUPPLYCHAININT",
                "expected_information_value": "Avoid one-metric abandonment claims.",
            })

    for p in packages:
        if not p.get("repository_id") or p.get("repository_relationship") == "UNKNOWN":
            gaps.append({
                "gap_id": stable_id("GAP", "pkg_repo", p["package_id"]),
                "type": "PACKAGE_REPO_MAPPING_UNRESOLVED",
                "importance": "HIGH",
                "package_id": p["package_id"],
                "recommended_source": "Package registry metadata, release provenance, SBOM, build attestation.",
                "specialist": "PACKAGEINT / REPOINT",
                "expected_information_value": "Connect published package to source repository without assuming.",
            })

    for d in dependencies:
        if d.get("version_constraint") and not d.get("resolved_version"):
            gaps.append({
                "gap_id": stable_id("GAP", "resolved_dep", d["dependency_id"]),
                "type": "DEPENDENCY_RESOLVED_VERSION_UNKNOWN",
                "importance": "MEDIUM",
                "dependency_id": d["dependency_id"],
                "recommended_source": "Lockfile, build log, SBOM, deployed artifact metadata.",
                "specialist": "REPOINT / SUPPLYCHAININT / VULNINT",
                "expected_information_value": "Avoid treating manifest range as deployed version.",
            })

    for s in sboms:
        gen = s.get("generated_at")
        if gen and (datetime.now(timezone.utc) - gen).days > 180:
            gaps.append({
                "gap_id": stable_id("GAP", "sbom_stale", s["sbom_id"]),
                "type": "SBOM_POSSIBLY_STALE",
                "importance": "MEDIUM",
                "sbom_id": s["sbom_id"],
                "recommended_source": "Fresh build-time SBOM, artifact manifest, lockfile.",
                "specialist": "REPOINT / SUPPLYCHAININT",
                "expected_information_value": "Prevent stale SBOM from being treated as current deployment.",
            })

    for w in workflows:
        for action in w.get("third_party_actions", []):
            if action.get("floating_reference"):
                gaps.append({
                    "gap_id": stable_id("GAP", "floating_action", w["workflow_id"], action.get("action", "")),
                    "type": "CI_THIRD_PARTY_ACTION_NOT_PINNED",
                    "importance": "MEDIUM",
                    "workflow_id": w["workflow_id"],
                    "action": action.get("action"),
                    "ref": action.get("ref"),
                    "recommended_source": "Workflow execution history, action release metadata, organizational policy.",
                    "specialist": "REPOINT / SUPPLYCHAININT",
                    "expected_information_value": "Defensive reproducibility/supply-chain signal only, not exploit guidance.",
                })

    for adv in advisories:
        gaps.append({
            "gap_id": stable_id("GAP", "advisory_applicability", adv["advisory_id"]),
            "type": "VULNERABILITY_APPLICABILITY_UNRESOLVED",
            "importance": "HIGH",
            "advisory_id": adv["advisory_id"],
            "recommended_source": "Affected version mapping, deployed version evidence, VEX, VULNINT analysis.",
            "specialist": "VULNINT / SUPPLYCHAININT",
            "expected_information_value": "Avoid equating CVE/advisory mention with affected deployment.",
        })

    for sec in secret_exposures:
        gaps.append({
            "gap_id": stable_id("GAP", "secret_remediation", sec["exposure_id"]),
            "type": "SECRET_REMEDIATION_UNKNOWN",
            "importance": "HIGH",
            "exposure_id": sec["exposure_id"],
            "recommended_source": "Owner-side rotation/revocation evidence, secret scanning status, CREDINT remediation workflow.",
            "specialist": "CREDINT / INCIDENTINT",
            "expected_information_value": "Distinguish exposed candidate from active credential without testing.",
        })

    for c in contradictions:
        gaps.append({
            "gap_id": stable_id("GAP", "contradiction", c["contradiction_id"]),
            "type": "REPOSITORY_CONTRADICTION_UNRESOLVED",
            "importance": "HIGH" if c.get("severity") == "MATERIAL" else "MEDIUM",
            "contradiction_id": c["contradiction_id"],
            "recommended_source": "Authoritative platform metadata, official docs, release provenance, history snapshots.",
            "specialist": "REPOINT / HUMAN_REVIEW",
            "expected_information_value": "Resolve conflicting repository/package/license/state claims.",
        })

    return gaps[:1000]


def build_next_actions(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    actions = []
    priority_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for g in gaps:
        if g["type"] == "CANONICAL_REPOSITORY_UNRESOLVED":
            action = "Retrieve official project documentation or package registry source link before treating repository as canonical."
        elif g["type"] == "LEGAL_OWNERSHIP_UNRESOLVED":
            action = "Separate hosting account from legal owner using corporate/official/licensing evidence; do not infer ownership from namespace."
        elif g["type"] == "LICENSE_UNRESOLVED":
            action = "Retrieve LICENSE file or package license metadata; do not assume public domain."
        elif g["type"] == "PACKAGE_REPO_MAPPING_UNRESOLVED":
            action = "Map package to repository via registry metadata, release provenance, or SBOM; do not equate package name with repo."
        elif g["type"] == "DEPENDENCY_RESOLVED_VERSION_UNKNOWN":
            action = "Use lockfile/build/SBOM evidence for resolved versions; manifest range is not deployment version."
        elif g["type"] == "SBOM_POSSIBLY_STALE":
            action = "Refresh SBOM from current build/artifact evidence before supply-chain conclusions."
        elif g["type"] == "CI_THIRD_PARTY_ACTION_NOT_PINNED":
            action = "Record defensive reproducibility concern; do not generate exploitation or attack guidance."
        elif g["type"] == "VULNERABILITY_APPLICABILITY_UNRESOLVED":
            action = "Handoff advisory/CVE to VULNINT for affected-version and applicability analysis."
        elif g["type"] == "SECRET_REMEDIATION_UNKNOWN":
            action = "Handoff secret candidate to CREDINT for remediation intelligence without authentication or validation."
        elif g["type"] == "REPOSITORY_CONTRADICTION_UNRESOLVED":
            action = "Resolve contradiction using authoritative metadata and temporal snapshots; preserve both states."
        else:
            action = "Gather additional authorized repository evidence."

        actions.append({
            "action": action,
            "gap_id": g.get("gap_id"),
            "priority": g.get("importance", "MEDIUM"),
            "expected_information_value": g.get("expected_information_value"),
            "prohibited_alternatives": [
                "Do not use discovered secrets.",
                "Do not validate secrets by login/API calls.",
                "Do not execute repository code or build artifacts.",
                "Do not submit malicious commits/PRs/MRs.",
                "Do not poison dependencies or packages.",
                "Do not access private repositories without authorization.",
            ],
        })
    actions.sort(key=lambda x: priority_map.get(x.get("priority", "LOW"), 9))
    return actions[:300]


def build_handoffs(
    repos: Dict[str, Dict[str, Any]],
    packages: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
    advisories: List[Dict[str, Any]],
    secret_exposures: List[Dict[str, Any]],
    workflows: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    health: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    hands = []
    seen = set()

    def add(spec: str, reason: str, payload: Dict[str, Any]) -> None:
        key = (spec, json_safe(payload))
        if key in seen:
            return
        seen.add(key)
        hands.append({
            "specialist": spec,
            "reason": reason,
            "payload": payload,
        })

    if packages:
        add("PACKAGEINT", "Package/repository publishing and registry mapping requires package specialist.", {
            "package_ids": [p["package_id"] for p in packages[:100]],
        })

    if dependencies:
        add("SUPPLYCHAININT", "Dependency graph and supply-chain propagation require supply-chain specialist.", {
            "dependency_count": len(dependencies),
            "sample_dependency_ids": [d["dependency_id"] for d in dependencies[:50]],
        })

    if advisories:
        add("VULNINT", "CVE/advisory applicability and fixed-version analysis required.", {
            "advisory_ids": [a["advisory_id"] for a in advisories[:100]],
        })

    if secret_exposures:
        add("CREDINT", "Secret exposure candidates require remediation intelligence without validation.", {
            "exposure_ids": [s["exposure_id"] for s in secret_exposures[:100]],
            "handling": ["REDACTED_ONLY", "NO_VALIDATION", "NO_USE"],
        })

    floating = [
        (w["workflow_id"], a)
        for w in workflows
        for a in w.get("third_party_actions", [])
        if a.get("floating_reference")
    ]
    if floating:
        add("SUPPLYCHAININT / CI_SECURITY", "CI third-party action references include floating refs; defensive reproducibility review.", {
            "workflow_ids": list(dict.fromkeys([w for w, _ in floating]))[:100],
        })

    if any(c.get("type") == "LICENSE_CONFLICT" for c in contradictions):
        add("LEGALINT", "License conflict requires legal review.", {
            "contradiction_ids": [c["contradiction_id"] for c in contradictions if c.get("type") == "LICENSE_CONFLICT"][:100],
        })

    if any(h.get("health_state") in {"ARCHIVED", "DEPRECATED", "ABANDONMENT_CANDIDATE"} for h in health.values()):
        add("SUPPLYCHAININT", "Lifecycle/deprecation/archival risk requires supply-chain continuity review.", {
            "repository_ids": [rid for rid, h in health.items() if h.get("health_state") in {"ARCHIVED", "DEPRECATED", "ABANDONMENT_CANDIDATE"}][:100],
        })

    if any(repo.get("access_state") == "ACCESS_UNKNOWN" for repo in repos.values()):
        add("HUMAN_REVIEW / AUTHORIZATION", "Repository access state unresolved; do not attempt unauthorized access.", {
            "repository_ids": [rid for rid, repo in repos.items() if repo.get("access_state") == "ACCESS_UNKNOWN"][:100],
        })

    return hands


def dual_ai_review_stub(
    repos: Dict[str, Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    secret_exposures: List[Dict[str, Any]],
    workflows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    review = {
        "status": "INSUFFICIENT_EVIDENCE",
        "primary_conclusions": [],
        "skeptic_challenges": [],
        "comparison": "NO_SECOND_MODEL_CONFIGURED",
        "notes": [
            "This starter does not call an independent second model.",
            "AI agreement is not independent repository evidence.",
            "Human review is required for consequential attribution, compromise claims, or legal/IP decisions.",
        ],
    }
    if repos:
        review["primary_conclusions"].append("Repository inventory constructed from provided records only.")
        review["skeptic_challenges"].append("Check canonical/fork/mirror status against official docs and package registry links.")
    if contradictions:
        review["primary_conclusions"].append(f"{len(contradictions)} repository/package/license contradiction candidate(s) detected.")
        review["skeptic_challenges"].append("Contradictions may be benign: migration, stale metadata, dual licensing, release automation, or mirror lag.")
    if secret_exposures:
        review["primary_conclusions"].append("Secret exposure candidates detected and redacted.")
        review["skeptic_challenges"].append("Secrets were not validated. Candidate may be test/example/false positive/rotated.")
    if workflows:
        review["primary_conclusions"].append("CI workflow metadata parsed statically.")
        review["skeptic_challenges"].append("Workflow file presence does not prove active pipeline; no exploitation guidance generated.")
    if review["primary_conclusions"]:
        review["status"] = "PARTIAL_AGREEMENT"
    return review


# --------------------------------------------------------------------
# Graph memory
# --------------------------------------------------------------------

class GraphMemory:
    def __init__(self) -> None:
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self._node_ids: Set[str] = set()

    def add_node(self, node_type: str, node_id: str, properties: Optional[Dict[str, Any]] = None) -> None:
        if not node_id or node_id in self._node_ids:
            return
        self._node_ids.add(node_id)
        self.nodes.append({"type": node_type, "id": node_id, "properties": properties or {}})

    def add_edge(self, from_id: str, to_id: str, edge_type: str, properties: Optional[Dict[str, Any]] = None) -> None:
        if not from_id or not to_id:
            return
        self.edges.append({
            "from": from_id,
            "to": to_id,
            "type": edge_type,
            "properties": properties or {},
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": self.nodes[:3000],
            "edges": self.edges[:6000],
            "note": "Repository graph preserves provenance, temporal state, and uncertainty. It does not prove legal ownership, real-person identity, deployment, or malice.",
        }


def build_graph_memory(
    repos: Dict[str, Dict[str, Any]],
    accounts: Dict[str, Dict[str, Any]],
    commits: List[Dict[str, Any]],
    branches: List[Dict[str, Any]],
    tags: List[Dict[str, Any]],
    releases: List[Dict[str, Any]],
    packages: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
    workflows: List[Dict[str, Any]],
    advisories: List[Dict[str, Any]],
    secret_exposures: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    maintainers: List[Dict[str, Any]],
    codeowners: List[Dict[str, Any]],
    contributors: Dict[str, Dict[str, Any]],
    hypotheses: List[Dict[str, Any]],
    contradictions: List[Dict[str, Any]],
    gaps: List[Dict[str, Any]],
) -> GraphMemory:
    g = GraphMemory()

    for repo in repos.values():
        g.add_node("Repository", repo["repository_id"], {
            "platform": repo.get("platform"),
            "canonical_url": repo.get("canonical_url"),
            "visibility": repo.get("visibility"),
            "access_state": repo.get("access_state"),
            "fork_state": repo.get("fork_state"),
            "mirror_state": repo.get("mirror_state"),
            "archived": repo.get("archived"),
        })

    for acc in accounts.values():
        g.add_node("Account", acc["account_id"], {
            "platform": acc.get("platform"),
            "account_type": acc.get("account_type"),
            "login": acc.get("login"),
        })

    for repo in repos.values():
        if repo.get("owner_account"):
            g.add_edge(repo["repository_id"], repo["owner_account"], "HOSTED_BY_ACCOUNT", {
                "legal_owner_established": False,
            })

    for rel in relationships:
        g.add_edge(rel["source_repository"], rel["target_repository"], rel["relationship_type"], {
            "relationship_id": rel["relationship_id"],
            "valid_from": iso(rel.get("valid_from")),
            "valid_to": iso(rel.get("valid_to")),
        })

    for c in commits:
        g.add_node("Commit", c["commit_id"], {
            "repository_id": c.get("repository_id"),
            "hash": c.get("hash"),
            "signature_state": c.get("signature_state"),
            "author_verified_real_person": False,
        })
        if c.get("repository_id"):
            g.add_edge(c["repository_id"], c["commit_id"], "CONTAINS_COMMIT", {})
        for parent in c.get("parents", []):
            g.add_edge(parent, c["commit_id"], "PARENT_OF_COMMIT", {})
        author_acc = c.get("author_identity", {}).get("account_id")
        if author_acc:
            g.add_edge(c["commit_id"], author_acc, "AUTHORED_BY_CLAIM", {"verified_real_person": False})
        committer_acc = c.get("committer_identity", {}).get("account_id")
        if committer_acc:
            g.add_edge(c["commit_id"], committer_acc, "COMMITTED_BY_CLAIM", {"verified_real_person": False})

    for b in branches:
        g.add_node("Branch", b["branch_id"], {"repository_id": b.get("repository_id"), "branch_name": b.get("branch_name")})
        if b.get("repository_id"):
            g.add_edge(b["repository_id"], b["branch_id"], "HAS_BRANCH", {})
        if b.get("head_commit"):
            g.add_edge(b["branch_id"], b["head_commit"], "HEAD_AT_COMMIT", {})

    for t in tags:
        g.add_node("Tag", t["tag_id"], {"repository_id": t.get("repository_id"), "tag": t.get("tag")})
        if t.get("repository_id"):
            g.add_edge(t["repository_id"], t["tag_id"], "HAS_TAG", {})
        if t.get("target_commit"):
            g.add_edge(t["tag_id"], t["target_commit"], "POINTS_TO_COMMIT", {})

    for r in releases:
        g.add_node("Release", r["release_id"], {"repository_id": r.get("repository_id"), "tag": r.get("tag")})
        if r.get("repository_id"):
            g.add_edge(r["repository_id"], r["release_id"], "HAS_RELEASE", {})
        if r.get("tag"):
            g.add_edge(r["release_id"], f"TAG::{r['repository_id']}::{r['tag']}", "REFERENCES_TAG", {"resolution": "by_tag_name"})

    for p in packages:
        g.add_node("Package", p["package_id"], {
            "ecosystem": p.get("ecosystem"),
            "package_name": p.get("package_name"),
            "version": p.get("version"),
        })
        if p.get("repository_id"):
            g.add_edge(p["package_id"], p["repository_id"], p.get("repository_relationship") or "REFERENCES", {})

    for d in dependencies:
        g.add_node("Dependency", d["dependency_id"], {
            "consumer_type": d.get("consumer_type"),
            "consumer_id": d.get("consumer_id"),
            "dependency_name": d.get("dependency_name"),
        })
        if d.get("consumer_id"):
            g.add_edge(d["consumer_id"], d["dependency_id"], "HAS_DEPENDENCY_SIGNAL", {})

    for w in workflows:
        g.add_node("Workflow", w["workflow_id"], {
            "repository_id": w.get("repository_id"),
            "platform": w.get("platform"),
            "path": w.get("path"),
        })
        if w.get("repository_id"):
            g.add_edge(w["repository_id"], w["workflow_id"], "USES_WORKFLOW", {})

    for a in advisories:
        g.add_node("SecurityAdvisory", a["advisory_id"], {
            "cve": a.get("cve"),
            "package_id": a.get("package_id"),
            "repository_id": a.get("repository_id"),
        })
        if a.get("repository_id"):
            g.add_edge(a["advisory_id"], a["repository_id"], "AFFECTS_REPOSITORY_CANDIDATE", {})
        if a.get("package_id"):
            g.add_edge(a["advisory_id"], a["package_id"], "AFFECTS_PACKAGE_CANDIDATE", {})

    for s in secret_exposures:
        g.add_node("SecretExposure", s["exposure_id"], {
            "location": s.get("location"),
            "state": s.get("state"),
            "fingerprint": s.get("fingerprint"),
            "validated": False,
        })

    for m in maintainers:
        if m.get("account_id") and m.get("repository_id"):
            g.add_edge(m["repository_id"], m["account_id"], "MAINTAINED_BY", {
                "maintainer_id": m["maintainer_id"],
                "employment_established": False,
            })

    for co in codeowners:
        owner = normalize_text(co.get("owner", "")).lstrip("@")
        if owner and co.get("repository_id"):
            g.add_edge(co["repository_id"], owner, "CODEOWNED_BY", {
                "path_pattern": co.get("path_pattern"),
                "legal_owner_established": False,
            })

    for c in contributors.values():
        g.add_node("Contributor", c["contributor_id"], {
            "roles": sorted(c.get("roles", [])),
            "commit_count": c.get("commit_count"),
            "real_person_verified": False,
        })

    for h in hypotheses[:1000]:
        g.add_node("Hypothesis", h["hypothesis_id"], {
            "statement": h["statement"],
            "status": h["status"],
            "subject_type": h.get("subject_type"),
            "subject_id": h.get("subject_id"),
        })

    for c in contradictions[:1000]:
        g.add_node("Contradiction", c["contradiction_id"], {
            "type": c["type"],
            "severity": c.get("severity"),
            "detail": c.get("detail"),
        })

    for gap in gaps[:1000]:
        g.add_node("Gap", gap["gap_id"], {
            "type": gap["type"],
            "importance": gap["importance"],
        })

    return g


# --------------------------------------------------------------------
# Result assembly
# --------------------------------------------------------------------

def empty_result(manifest: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "case_id": manifest.get("case_id", "CASE-UNKNOWN"),
        "task_id": manifest.get("task_id", "TASK-UNKNOWN"),
        "objective": manifest.get("objective", ""),
        "questions": manifest.get("questions", []) or [],
        "generated_at": utc_now(),
        "version": VERSION,
        "source_ids": [],
        "evidence_ids": [],
        "repositories": [],
        "repository_hosts": [],
        "owner_accounts": [],
        "projects": [],
        "canonical_repositories": [],
        "forks": [],
        "mirrors": [],
        "derived_repositories": [],
        "repository_genealogy": [],
        "repository_control_eras": [],
        "branches": [],
        "tags": [],
        "releases": [],
        "release_artifacts": [],
        "commits": [],
        "commit_graph": [],
        "commit_authors": [],
        "committers": [],
        "contributors": [],
        "maintainers": [],
        "codeowners": [],
        "organization_context": [],
        "repository_transfers": [],
        "issues": [],
        "pull_requests": [],
        "merge_requests": [],
        "discussions": [],
        "wikis": [],
        "languages": [],
        "technology_stack": [],
        "file_tree_context": [],
        "feature_candidates": [],
        "stub_placeholders": [],
        "tests_context": [],
        "manifests": [],
        "lockfiles": [],
        "packages": [],
        "package_versions": [],
        "repository_package_relationships": [],
        "dependencies": [],
        "dependency_depth": [],
        "dependency_scopes": [],
        "sboms": [],
        "vex_records": [],
        "licenses": [],
        "ci_cd_workflows": [],
        "workflow_permissions": [],
        "third_party_actions": [],
        "build_pipeline_context": [],
        "artifact_registries": [],
        "container_context": [],
        "release_signatures": [],
        "commit_signatures": [],
        "tag_signatures": [],
        "security_advisories": [],
        "cve_references": [],
        "security_fix_candidates": [],
        "secret_exposure_candidates": [],
        "secret_fingerprints": [],
        "secret_remediation_context": [],
        "project_health": [],
        "maintainer_concentration": [],
        "deprecation_state": [],
        "archival_state": [],
        "successor_projects": [],
        "timeline_updates": [],
        "observations": [],
        "candidate_facts": [],
        "supported_facts": [],
        "partial_facts": [],
        "disputed_facts": [],
        "source_reliability": [],
        "source_bias": [],
        "source_limitations": [],
        "source_pedigree": [],
        "source_independence": [],
        "contradictions": [],
        "hypotheses": [],
        "ach_matrix": [],
        "falsification_results": [],
        "privacy_flags": [],
        "legal_flags": [],
        "unknowns": [],
        "knowledge_gaps": [],
        "recommended_next_actions": [],
        "specialist_handoffs": [],
        "limitations": [],
        "dual_ai_review": {},
        "graph_memory": {},
        "status": "PARTIAL",
    }


def summarize_repo(repo: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(repo)
    for k in ("created_at", "first_seen", "last_seen", "archived_at"):
        if k in out:
            out[k] = iso(out[k])
    return out


def summarize_commit(c: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(c)
    out["author_timestamp"] = iso(c.get("author_timestamp"))
    out["commit_timestamp"] = iso(c.get("commit_timestamp"))
    return out


def summarize_release(r: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(r)
    out["published_at"] = iso(r.get("published_at"))
    return out


def finalize_status(
    result: Dict[str, Any],
    repos: Dict[str, Dict[str, Any]],
    auth_ok: bool,
    policy_blocked: List[str],
) -> str:
    if policy_blocked:
        return "POLICY_BLOCKED"
    if not auth_ok:
        return "BLOCKED_PERMISSION"
    if not repos:
        return "INSUFFICIENT_INPUT"
    if result.get("contradictions"):
        return "PARTIAL"
    if result.get("knowledge_gaps"):
        return "PARTIAL"
    if any(r.get("access_state") == "ACCESS_UNKNOWN" for r in repos.values()):
        return "PARTIAL"
    return "SUCCEEDED"


def analyze_repoint_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    result = empty_result(manifest)

    policy_blocked = policy_screen(manifest)
    if policy_blocked:
        result["status"] = "POLICY_BLOCKED"
        result["violations"] = policy_blocked
        result["privacy_flags"] = [{"type": label, "action": "PROHIBITED_REQUEST_NOT_PERFORMED"} for label in policy_blocked]
        result["limitations"] = [
            "REPOINT does not access unauthorized private repositories, use stolen credentials, validate secrets, execute untrusted code, or perform supply-chain attacks."
        ]
        return result

    auth_ok, auth_reasons = authorization_check(manifest)
    if not auth_ok:
        result["status"] = "BLOCKED_PERMISSION"
        result["limitations"] = auth_reasons
        return result

    privacy_cfg = privacy_config(manifest)
    as_of = parse_time(manifest.get("as_of")) or datetime.now(timezone.utc)

    sources = ingest_sources(manifest)
    source_roots = build_source_roots(sources)

    repos, accounts, privacy_flags = ingest_repositories(manifest, sources, privacy_cfg)
    accounts = ingest_accounts(manifest, accounts)

    commits, contributors, commit_secrets = ingest_commits(manifest, repos, accounts, privacy_cfg)
    branches = ingest_branches(manifest, repos)
    tags = ingest_tags(manifest, repos)
    releases = ingest_releases(manifest, repos)
    packages = ingest_packages(manifest, repos)
    dependencies = ingest_dependencies(manifest)
    sboms = ingest_sboms(manifest)
    advisories = ingest_advisories(manifest)
    relationships = ingest_repository_relationships(manifest, repos)
    control_eras = ingest_control_eras(manifest, repos, accounts)
    maintainers, codeowners = ingest_roles(manifest, repos, accounts, contributors)

    file_artifacts = ingest_repository_files(manifest, repos, accounts, contributors)
    dependencies.extend(file_artifacts["dependencies"])
    sboms.extend(file_artifacts["sboms"])
    workflows = file_artifacts["workflows"] + [
        w for w in manifest.get("ci_workflows", []) or []
    ]
    codeowners.extend(file_artifacts["codeowners"])
    secret_exposures = commit_secrets + file_artifacts["secret_exposures"]
    licenses_detected = file_artifacts["licenses"]
    deprecation_info = file_artifacts["deprecation"]

    # Bot detection / contributor normalization.
    for cid, c in contributors.items():
        acc = accounts.get(c.get("account_id") or cid, {})
        login = normalize_text(acc.get("login") or cid).lower()
        atype = normalize_text(acc.get("account_type")).upper()
        if atype == "BOT" or login.endswith("bot") or "[bot]" in login or "dependabot" in login or "renovate" in login:
            c["roles"].add("BOT_CANDIDATE")

    # Source independence per repository.
    repo_source_independence = {}
    for repo_id in repos:
        repo_source_independence[repo_id] = compute_repo_source_independence(
            repo_id, repos, commits, releases, relationships, sources, source_roots
        )

    # Project health.
    health = {}
    for repo_id, repo in repos.items():
        health[repo_id] = compute_project_health(repo, commits, releases, maintainers, deprecation_info, as_of)

    contradictions = detect_contradictions(
        repos, commits, tags, releases, packages, maintainers, accounts, licenses_detected, relationships
    )

    hypotheses = generate_hypotheses(repos, relationships, packages, secret_exposures, releases)
    ach = build_ach_stub(hypotheses)

    gaps = build_gaps(
        repos, packages, dependencies, sboms, workflows, advisories,
        secret_exposures, licenses_detected, health, contradictions
    )
    actions = build_next_actions(gaps)
    handoffs = build_handoffs(repos, packages, dependencies, advisories, secret_exposures, workflows, contradictions, health)
    dual_review = dual_ai_review_stub(repos, contradictions, secret_exposures, workflows)
    graph = build_graph_memory(
        repos, accounts, commits, branches, tags, releases, packages, dependencies,
        workflows, advisories, secret_exposures, relationships, maintainers, codeowners,
        contributors, hypotheses, contradictions, gaps
    )

    # Observations.
    observations = [
        f"Repositories ingested/resolved: {len(repos)}.",
        f"Commits ingested: {len(commits)}.",
        f"Releases ingested: {len(releases)}.",
        f"Packages referenced: {len(packages)}.",
        f"Dependencies captured: {len(dependencies)}.",
        f"SBOM documents parsed/provided: {len(sboms)}.",
        f"CI workflows parsed statically: {len(workflows)}.",
        f"Security advisories ingested: {len(advisories)}.",
        f"Secret exposure candidates detected and redacted: {len(secret_exposures)}.",
        f"Contradiction candidates: {len(contradictions)}.",
        "No network access, no private repository access, no secret validation, and no code execution were performed.",
        "Repository hosting account was not equated with legal owner.",
        "Contributor was not equated with employee, maintainer, or verified real person.",
        "Commit was not equated with release or deployment.",
    ]

    unknowns = []
    for repo_id, repo in repos.items():
        if repo.get("fork_state") == "UNKNOWN":
            unknowns.append(f"Repository {repo_id} canonical/fork/mirror state unresolved.")
        if repo.get("access_state") == "ACCESS_UNKNOWN":
            unknowns.append(f"Repository {repo_id} access state unresolved; no unauthorized access attempted.")
    for sec in secret_exposures:
        unknowns.append(f"Secret exposure {sec['exposure_id']} validity/remediation unresolved; not tested.")
    for r in releases:
        unknowns.append(f"Release {r['release_id']} deployment status unresolved.")
    unknowns = list(dict.fromkeys(unknowns))[:500]

    # Populate result.
    result["repositories"] = [summarize_repo(r) for r in repos.values()]
    result["repository_hosts"] = sorted({r.get("host") for r in repos.values() if r.get("host")})
    result["owner_accounts"] = [accounts[a] for a in sorted({r.get("owner_account") for r in repos.values() if r.get("owner_account")})]
    result["canonical_repositories"] = [rid for rid, r in repos.items() if r.get("fork_state") == "CANONICAL"]
    result["forks"] = [rid for rid, r in repos.items() if r.get("fork_state") == "FORK"]
    result["mirrors"] = [rid for rid, r in repos.items() if r.get("mirror_state") == "MIRROR"]
    result["derived_repositories"] = [rel for rel in relationships if rel.get("relationship_type") in {"DERIVED_FROM", "MIGRATED_FROM", "SUCCESSOR_OF", "SPLIT_FROM", "MERGED_INTO"}]
    result["repository_genealogy"] = relationships
    result["repository_control_eras"] = control_eras
    result["branches"] = branches
    result["tags"] = tags
    result["releases"] = [summarize_release(r) for r in releases]
    result["release_artifacts"] = [a for r in releases for a in r.get("artifacts", [])]
    result["commits"] = [summarize_commit(c) for c in commits]
    result["commit_graph"] = [
        {"commit_id": c["commit_id"], "parents": c.get("parents", [])}
        for c in commits
    ]
    result["commit_authors"] = [
        {
            "commit_id": c["commit_id"],
            "author_identity": c.get("author_identity"),
            "author_timestamp": iso(c.get("author_timestamp")),
        }
        for c in commits
    ]
    result["committers"] = [
        {
            "commit_id": c["commit_id"],
            "committer_identity": c.get("committer_identity"),
            "commit_timestamp": iso(c.get("commit_timestamp")),
        }
        for c in commits
    ]
    result["contributors"] = [
        {
            "contributor_id": c["contributor_id"],
            "account_id": c.get("account_id"),
            "display_name": c.get("display_name"),
            "roles": sorted(c.get("roles", [])),
            "repositories": sorted(c.get("repositories", [])),
            "commit_count": c.get("commit_count"),
            "first_seen": iso(c.get("first_seen")),
            "last_seen": iso(c.get("last_seen")),
            "real_person_verified": False,
            "limitations": c.get("limitations", []),
        }
        for c in contributors.values()
    ]
    result["maintainers"] = maintainers
    result["codeowners"] = codeowners
    result["packages"] = packages
    result["package_versions"] = [{"package_id": p["package_id"], "version": p.get("version")} for p in packages]
    result["repository_package_relationships"] = [
        {"package_id": p["package_id"], "repository_id": p.get("repository_id"), "relationship": p.get("repository_relationship")}
        for p in packages
    ]
    result["dependencies"] = dependencies
    result["dependency_depth"] = [{"dependency_id": d["dependency_id"], "depth": d.get("dependency_depth")} for d in dependencies]
    result["dependency_scopes"] = [{"dependency_id": d["dependency_id"], "scope": d.get("dependency_type")} for d in dependencies]
    result["sboms"] = sboms
    result["licenses"] = [
        {"repository_id": rid, **lic}
        for rid, lic in licenses_detected.items()
    ] + [
        {"repository_id": rid, "license_identifier": r.get("license"), "source": "repository_metadata"}
        for rid, r in repos.items()
        if r.get("license")
    ]
    result["ci_cd_workflows"] = workflows
    result["workflow_permissions"] = [
        {"workflow_id": w["workflow_id"], "permissions": w.get("permissions", [])}
        for w in workflows
    ]
    result["third_party_actions"] = [
        {"workflow_id": w["workflow_id"], **a}
        for w in workflows
        for a in w.get("third_party_actions", [])
    ]
    result["security_advisories"] = advisories
    result["cve_references"] = [{"advisory_id": a["advisory_id"], "cve": a.get("cve")} for a in advisories if a.get("cve")]
    result["secret_exposure_candidates"] = secret_exposures
    result["secret_fingerprints"] = [{"exposure_id": s["exposure_id"], "fingerprint": s["fingerprint"]} for s in secret_exposures]
    result["secret_remediation_context"] = [
        {
            "exposure_id": s["exposure_id"],
            "state": s["state"],
            "validated": False,
            "raw_value_stored": False,
            "remediation_evidence": "NOT_PROVIDED",
        }
        for s in secret_exposures
    ]
    result["project_health"] = list(health.values())
    result["maintainer_concentration"] = [
        {
            "repository_id": rid,
            "active_maintainer_count": h.get("maintainer_count"),
            "bus_factor_candidate": h.get("bus_factor_candidate"),
        }
        for rid, h in health.items()
    ]
    result["deprecation_state"] = [
        {"repository_id": rid, **info}
        for rid, info in deprecation_info.items()
    ]
    result["archival_state"] = [
        {"repository_id": rid, "archived": r.get("archived"), "archived_at": iso(r.get("archived_at"))}
        for rid, r in repos.items()
    ]
    result["file_tree_context"] = file_artifacts["file_inventory"]
    result["contradictions"] = contradictions
    result["hypotheses"] = hypotheses
    result["ach_matrix"] = ach
    result["falsification_results"] = [
        {
            "hypothesis_id": h["hypothesis_id"],
            "opposition": [x for x in h.get("opposition", []) if x],
            "falsification_conditions": h.get("falsification_conditions", []),
        }
        for h in hypotheses
    ]
    result["observations"] = observations
    result["unknowns"] = unknowns
    result["knowledge_gaps"] = gaps
    result["recommended_next_actions"] = actions
    result["specialist_handoffs"] = handoffs
    result["dual_ai_review"] = dual_review
    result["graph_memory"] = graph.to_dict()
    result["privacy_flags"] = privacy_flags + [
        {"type": "SECRET_RAW_VALUE_NOT_STORED", "action": "REDACTED_AND_FINGERPRINTED_ONLY"}
    ] if secret_exposures else privacy_flags

    for sid, src in sources.items():
        result["source_ids"].append(sid)
        result["source_reliability"].append({
            "source_id": sid,
            "source_type": src.get("source_type"),
            "reliability": src.get("reliability"),
        })
        result["source_pedigree"].append({
            "source_id": sid,
            "upstream_source_id": src.get("upstream_source_id"),
            "root_source_id": source_roots.get(sid, sid),
        })

    for repo_id, indep in repo_source_independence.items():
        result["source_independence"].append({"repository_id": repo_id, **indep})

    for c in commits:
        for evid in c.get("evidence_ids", []):
            result["evidence_ids"].append(evid)

    for r in repos.values():
        if r.get("fork_state") == "CANONICAL":
            result["supported_facts"].append({"repository_id": r["repository_id"], "statement": "Repository marked canonical from provided metadata; requires official-doc corroboration for consequential use."})
        elif r.get("fork_state") == "FORK":
            result["candidate_facts"].append({"repository_id": r["repository_id"], "statement": "Repository marked fork from provided metadata."})
        else:
            result["partial_facts"].append({"repository_id": r["repository_id"], "statement": "Repository canonicality unresolved."})

    for s in secret_exposures:
        result["candidate_facts"].append({
            "exposure_id": s["exposure_id"],
            "statement": "Secret exposure candidate detected and redacted; validity not tested.",
        })

    base_limits = [
        "REPOINT starter uses only provided/local authorized records; no network lookup, clone, API call, or private access was performed.",
        "Repository hosting account is not automatically legal owner.",
        "Contributor is not automatically employee, maintainer, code owner, or verified real person.",
        "Commit author/committer metadata is not verified real-person identity.",
        "Commit does not prove merge, release, build, or deployment.",
        "Release does not prove stable or deployed status.",
        "Package is not repository; publisher is not necessarily maintainer or legal owner.",
        "Manifest version ranges are not resolved/deployed versions without lockfile/build/SBOM evidence.",
        "SBOM may be stale/incomplete/build-specific.",
        "CI workflow file presence does not prove active pipeline.",
        "Secret candidates were redacted and fingerprinted only; never validated or used.",
        "No untrusted code, binary, container, notebook, model, or install script was executed.",
        "No supply-chain attack, dependency confusion, typosquatting, malicious commit/PR, or CI compromise was performed or assisted.",
    ]
    if auth_reasons:
        base_limits.extend(auth_reasons)
    result["limitations"] = list(dict.fromkeys(base_limits))

    result["status"] = finalize_status(result, repos, auth_ok, policy_blocked)
    return result


# --------------------------------------------------------------------
# Report generation
# --------------------------------------------------------------------

def generate_report(result: Dict[str, Any]) -> str:
    lines = []
    lines.append("# REPOINT Evidence-Linked Repository Report")
    lines.append("")
    lines.append(f"- Case ID: `{result.get('case_id')}`")
    lines.append(f"- Task ID: `{result.get('task_id')}`")
    lines.append(f"- Generated: `{result.get('generated_at')}`")
    lines.append(f"- Version: `{result.get('version')}`")
    lines.append(f"- Status: `{result.get('status')}`")
    lines.append("")

    if result.get("status") == "POLICY_BLOCKED":
        lines.append("## POLICY BLOCKED")
        lines.append("The request violated REPOINT hard restrictions:")
        for v in result.get("violations", []):
            lines.append(f"- `{v}`")
        lines.append("")
        lines.append("No repository intelligence was performed.")
        return "\n".join(lines)

    lines.append("## Objective")
    lines.append(str(result.get("objective", "")))
    lines.append("")

    lines.append("## Required Analyst Summary")
    repos = result.get("repositories", [])
    lines.append(f"- REPOSITORIES: {len(repos)}")
    lines.append(f"- CANONICAL MARKED: {len(result.get('canonical_repositories', []))}")
    lines.append(f"- FORKS MARKED: {len(result.get('forks', []))}")
    lines.append(f"- MIRRORS MARKED: {len(result.get('mirrors', []))}")
    lines.append(f"- COMMITS: {len(result.get('commits', []))}")
    lines.append(f"- RELEASES: {len(result.get('releases', []))}")
    lines.append(f"- PACKAGES: {len(result.get('packages', []))}")
    lines.append(f"- DEPENDENCIES: {len(result.get('dependencies', []))}")
    lines.append(f"- SBOMS: {len(result.get('sboms', []))}")
    lines.append(f"- CI WORKFLOWS: {len(result.get('ci_cd_workflows', []))}")
    lines.append(f"- ADVISORIES: {len(result.get('security_advisories', []))}")
    lines.append(f"- SECRET CANDIDATES: {len(result.get('secret_exposure_candidates', []))}")
    lines.append(f"- CONTRADICTIONS: {len(result.get('contradictions', []))}")
    lines.append(f"- KNOWLEDGE GAPS: {len(result.get('knowledge_gaps', []))}")
    lines.append("- NEXT ACTION: " + (result.get("recommended_next_actions", [{}])[0].get("action", "None") if result.get("recommended_next_actions") else "None"))
    lines.append("")

    lines.append("## Privacy / Repository Boundaries")
    lines.append("- No unauthorized private repository access.")
    lines.append("- No stolen tokens, cookies, SSH keys, or credential use.")
    lines.append("- No secret validation or authentication attempts.")
    lines.append("- No execution of untrusted code, binaries, containers, notebooks, models, or install scripts.")
    lines.append("- No malicious commits/PRs/MRs, dependency poisoning, typosquatting, or CI compromise.")
    lines.append("- Repository hosting account ≠ legal owner.")
    lines.append("- Contributor ≠ employee/maintainer/verified real person.")
    lines.append("- Commit ≠ merged ≠ released ≠ deployed.")
    lines.append("")

    lines.append("## Repository Inventory")
    for r in repos[:200]:
        lines.append(f"### `{r.get('repository_id')}`")
        lines.append(f"- Platform/host: `{r.get('platform')}` / `{r.get('host')}`")
        lines.append(f"- Canonical URL: `{r.get('canonical_url')}`")
        lines.append(f"- Owner account: `{r.get('owner_account')}` (not legal owner by itself)")
        lines.append(f"- Visibility/access: `{r.get('visibility')}` / `{r.get('access_state')}`")
        lines.append(f"- Fork/mirror: `{r.get('fork_state')}` / `{r.get('mirror_state')}`")
        lines.append(f"- Upstream: `{r.get('upstream_repository')}`")
        lines.append(f"- Default branch: `{r.get('default_branch')}`")
        lines.append(f"- Archived: `{r.get('archived')}` at `{r.get('archived_at')}`")
        lines.append(f"- License metadata: `{r.get('license')}`")
        lines.append(f"- Languages: {', '.join(r.get('languages', [])[:20]) or 'None'}")
        lines.append("")

    lines.append("## Repository Genealogy / Relationships")
    for rel in result.get("repository_genealogy", [])[:200]:
        lines.append(f"- `{rel.get('source_repository')}` --`{rel.get('relationship_type')}`--> `{rel.get('target_repository')}` valid `{rel.get('valid_from')}` to `{rel.get('valid_to')}`")
    lines.append("")

    lines.append("## Control Eras")
    for era in result.get("repository_control_eras", [])[:200]:
        lines.append(f"- `{era.get('era_id')}` repo=`{era.get('repository_id')}` owner=`{era.get('owner_account')}` valid=`{iso(era.get('valid_from')) if isinstance(era.get('valid_from'), datetime) else era.get('valid_from')}` to `{iso(era.get('valid_to')) if isinstance(era.get('valid_to'), datetime) else era.get('valid_to')}`")
    lines.append("")

    lines.append("## Commits / Authors / Committers")
    for c in result.get("commits", [])[:200]:
        lines.append(f"### `{c.get('commit_id')}`")
        lines.append(f"- Repository: `{c.get('repository_id')}` hash=`{c.get('hash')}`")
        lines.append(f"- Author claim: {json.dumps(c.get('author_identity'), ensure_ascii=False)}"[:500])
        lines.append(f"- Committer claim: {json.dumps(c.get('committer_identity'), ensure_ascii=False)}"[:500])
        lines.append(f"- Timestamps: author=`{c.get('author_timestamp')}` commit=`{c.get('commit_timestamp')}`")
        lines.append(f"- Signature: `{c.get('signature_state')}`")
        lines.append(f"- Message redacted: {c.get('message_redacted')}"[:500])
        lines.append("")

    lines.append("## Contributors / Maintainers / Codeowners")
    for c in result.get("contributors", [])[:200]:
        lines.append(f"- Contributor `{c.get('contributor_id')}` roles={c.get('roles')} commits={c.get('commit_count')} real_person_verified={c.get('real_person_verified')}")
    for m in result.get("maintainers", [])[:200]:
        lines.append(f"- Maintainer `{m.get('account_id')}` repo=`{m.get('repository_id')}` role=`{m.get('role')}` valid=`{m.get('valid_from')}` to `{m.get('valid_to')}`")
    for co in result.get("codeowners", [])[:200]:
        lines.append(f"- Codeowner `{co.get('owner')}` repo=`{co.get('repository_id')}` path=`{co.get('path_pattern')}`")
    lines.append("")

    lines.append("## Branches / Tags / Releases")
    for b in result.get("branches", [])[:200]:
        lines.append(f"- Branch `{b.get('branch_name')}` repo=`{b.get('repository_id')}` head=`{b.get('head_commit')}` default={b.get('default_state')}")
    for t in result.get("tags", [])[:200]:
        lines.append(f"- Tag `{t.get('tag')}` repo=`{t.get('repository_id')}` target=`{t.get('target_commit')}` signature=`{t.get('signature_state')}`")
    for r in result.get("releases", [])[:200]:
        lines.append(f"- Release `{r.get('release_id')}` repo=`{r.get('repository_id')}` tag=`{r.get('tag')}` published=`{r.get('published_at')}` prerelease={r.get('prerelease')}")
        for a in r.get("artifacts", [])[:20]:
            lines.append(f"  - Artifact `{a.get('name')}` kind=`{a.get('kind')}` checksum=`{a.get('checksum_algorithm')}:{mask_value(a.get('checksum'))}`")
    lines.append("")

    lines.append("## Packages / Dependencies / SBOM")
    for p in result.get("packages", [])[:200]:
        lines.append(f"- Package `{p.get('ecosystem')}:{p.get('package_name')}@{p.get('version')}` id=`{p.get('package_id')}` repo=`{p.get('repository_id')}` relationship=`{p.get('repository_relationship')}`")
    for d in result.get("dependencies", [])[:300]:
        lines.append(f"- Dependency `{d.get('consumer_type')}:{d.get('consumer_id')}` -> `{d.get('ecosystem')}:{d.get('dependency_name')}` constraint=`{d.get('version_constraint')}` resolved=`{d.get('resolved_version')}` type=`{d.get('dependency_type')}` directness=`{d.get('directness')}` depth={d.get('dependency_depth')}")
    for s in result.get("sboms", [])[:100]:
        lines.append(f"- SBOM `{s.get('sbom_id')}` format=`{s.get('format')}` repo=`{s.get('repository_id')}` generated=`{s.get('generated_at')}` components={len(s.get('components', []))}")
    lines.append("")

    lines.append("## CI/CD Workflows")
    for w in result.get("ci_cd_workflows", [])[:200]:
        lines.append(f"### `{w.get('workflow_id')}`")
        lines.append(f"- Repository: `{w.get('repository_id')}` platform=`{w.get('platform')}` path=`{w.get('path')}`")
        lines.append(f"- Triggers: {', '.join(w.get('triggers', [])) or 'None detected statically'}")
        lines.append(f"- Secret references: {', '.join(w.get('secret_references', [])) or 'None'}")
        lines.append(f"- Permissions: {json.dumps(w.get('permissions', []), ensure_ascii=False)}"[:500])
        for a in w.get("third_party_actions", [])[:50]:
            lines.append(f"  - Third-party action `{a.get('action')}` ref=`{a.get('ref')}` pinned={a.get('pinned_to_commit')} floating={a.get('floating_reference')}")
        lines.append("")

    lines.append("## Security Advisories / CVE References")
    for a in result.get("security_advisories", [])[:200]:
        lines.append(f"- `{a.get('advisory_id')}` CVE=`{a.get('cve')}` GHSA=`{a.get('ghsa')}` repo=`{a.get('repository_id')}` package=`{a.get('package_id')}` affected=`{a.get('affected_versions')}` fixed=`{a.get('fixed_versions')}`")
    lines.append("")

    lines.append("## Secret Exposure Candidates")
    for s in result.get("secret_exposure_candidates", [])[:200]:
        lines.append(f"- `{s.get('exposure_id')}` type=`{s.get('secret_type')}` state=`{s.get('state')}` location=`{s.get('location')}` line={s.get('line')} fingerprint=`{s.get('fingerprint')}` redacted=`{s.get('redacted_value')}`")
        lines.append(f"  - validated={s.get('validated')} raw_stored={s.get('raw_value_stored')}")
    lines.append("")

    lines.append("## Project Health")
    for h in result.get("project_health", [])[:200]:
        lines.append(f"- `{h.get('repository_id')}` state=`{h.get('health_state')}` archived={h.get('archived')} deprecation_candidate={h.get('deprecation_candidate')} latest_commit=`{h.get('latest_commit')}` latest_release=`{h.get('latest_release')}` maintainers={h.get('maintainer_count')} bus_factor_candidate={h.get('bus_factor_candidate')}")
    lines.append("")

    lines.append("## Contradictions")
    for c in result.get("contradictions", [])[:200]:
        lines.append(f"- `{c.get('contradiction_id')}` [{c.get('severity')}] {c.get('type')}: {c.get('detail')}")
        if c.get("possible_causes"):
            lines.append(f"  - possible causes: {'; '.join(c['possible_causes'])}")
    lines.append("")

    lines.append("## Hypotheses / ACH")
    for h in result.get("hypotheses", [])[:300]:
        lines.append(f"- `{h.get('hypothesis_id')}` [{h.get('status')}] {h.get('subject_type')} `{h.get('subject_id')}`: {h.get('statement')}")
        if h.get("support"):
            lines.append(f"  - support: {'; '.join(map(str, h['support'][:5]))}")
        if h.get("opposition"):
            lines.append(f"  - opposition: {'; '.join(map(str, [x for x in h['opposition'] if x][:5]))}")
        if h.get("falsification_conditions"):
            lines.append(f"  - falsify if: {'; '.join(map(str, h['falsification_conditions'][:5]))}")
    lines.append("")

    lines.append("## Knowledge Gaps")
    for g in result.get("knowledge_gaps", [])[:300]:
        lines.append(f"- `{g.get('gap_id')}` [{g.get('importance')}] {g.get('type')}: {g.get('recommended_source')}")
    lines.append("")

    lines.append("## Recommended Next Actions")
    for a in result.get("recommended_next_actions", [])[:300]:
        lines.append(f"- [{a.get('priority')}] {a.get('action')}")
    lines.append("")

    lines.append("## Specialist Handoffs")
    for h in result.get("specialist_handoffs", []):
        lines.append(f"- {h.get('specialist')}: {h.get('reason')}")
        lines.append(f"  - payload: `{json.dumps(h.get('payload', {}), ensure_ascii=False, default=str)}`"[:700])
    lines.append("")

    lines.append("## Dual-AI Review Stub")
    dr = result.get("dual_ai_review", {})
    lines.append(f"- Status: `{dr.get('status')}`")
    lines.append(f"- Comparison: `{dr.get('comparison')}`")
    for n in dr.get("notes", []):
        lines.append(f"- {n}")
    for c in dr.get("primary_conclusions", [])[:50]:
        lines.append(f"- Primary: {c}")
    for c in dr.get("skeptic_challenges", [])[:50]:
        lines.append(f"- Skeptic: {c}")
    lines.append("")

    lines.append("## Limitations")
    for lim in result.get("limitations", []):
        lines.append(f"- {lim}")
    lines.append("")

    lines.append("## Non-Negotiable Boundary")
    lines.append("- Resolve the repository.")
    lines.append("- Find the real upstream.")
    lines.append("- Trace its history.")
    lines.append("- Separate account from real person.")
    lines.append("- Separate contributor from maintainer.")
    lines.append("- Separate repository from package.")
    lines.append("- Separate commit from release.")
    lines.append("- Separate release from deployment.")
    lines.append("- Parse dependencies deterministically.")
    lines.append("- Verify the SBOM.")
    lines.append("- Analyze CI/CD passively.")
    lines.append("- Redact secrets.")
    lines.append("- Never test a secret.")
    lines.append("- Preserve provenance.")
    lines.append("- Attribute last.")

    return "\n".join(lines)


# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="TRACEATLAS REPOINT safe starter")
    parser.add_argument("--manifest", required=True, help="Path to REPOINT manifest JSON")
    parser.add_argument("--output", default="repoint_result.json", help="Output JSON path")
    parser.add_argument("--report", default="repoint_report.md", help="Output Markdown report path")
    args = parser.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"ERROR reading manifest: {exc}", file=sys.stderr)
        return 2

    result = analyze_repoint_manifest(manifest)

    Path(args.output).write_text(
        json.dumps(json_safe(result), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    Path(args.report).write_text(generate_report(result), encoding="utf-8")

    print(f"Wrote: {args.output}")
    print(f"Wrote: {args.report}")
    return 0

# Interrupted upload example preserved in packages/archive_sources/intelligence-suite.
