from __future__ import annotations

import base64
import csv
import hashlib
import html
import json
import os
import re
import tempfile
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen
from uuid import uuid4

from ..db import CaseDB
from ..capabilities.service import ServiceClient
from ..evidence import EvidenceStore, sha256_file
from ..policy import PolicyError, validate_target
from ..spider.events import Event, child
from .policy import (
    fingerprint, minimize_breach, require_sensitive_policy, validate_bssid, validate_sha1,
)


MAX_RESPONSE = 2 * 1024 * 1024
MAX_ARTIFACT = 32 * 1024 * 1024


def _http_get(url: str, headers: dict[str, str], timeout: int = 20) -> tuple[int, bytes]:
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE)
    except HTTPError as exc:
        return exc.code, exc.read(MAX_RESPONSE)
    except (URLError, TimeoutError, OSError):
        return 0, b""


def _json_or(body: bytes, default: Any) -> Any:
    try:
        return json.loads(body) if body else default
    except (json.JSONDecodeError, UnicodeDecodeError):
        return default


def _string_list(value: Any, *, limit: int = 100, width: int = 160) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item)[:width] for item in value[:limit] if isinstance(item, (str, int))]


def _coarse_coordinate(value: Any, minimum: float, maximum: float) -> float | None:
    try:
        coordinate = float(value)
    except (TypeError, ValueError):
        return None
    if not minimum <= coordinate <= maximum:
        return None
    return round(coordinate, 2)


def _optional_text(value: Any, width: int) -> str | None:
    return str(value)[:width] if isinstance(value, (str, int, float)) else None


class _AhmiaLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.current_href: str | None = None
        self.current_text: list[str] = []
        self.results: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href") or ""
        if ".onion" in href.lower():
            self.current_href = href
            self.current_text = []

    def handle_data(self, data: str) -> None:
        if self.current_href:
            self.current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or not self.current_href:
            return
        host = (urlparse(self.current_href).hostname or "").lower()
        if host.endswith(".onion"):
            title = " ".join("".join(self.current_text).split())[:200]
            self.results.append({
                "service_fingerprint": hashlib.sha256(host.encode()).hexdigest(),
                "title": html.unescape(title),
            })
        self.current_href = None
        self.current_text = []


class SensitiveRunner:
    def __init__(self, db: CaseDB, workspace: Path,
                 http_get: Callable[[str, dict[str, str], int], tuple[int, bytes]] | None = None):
        self.db = db
        self.workspace = workspace
        self.http_get = http_get or _http_get

    def _begin(self, case_id: str, workflow: str, target: str, lawful_purpose: str,
               attestations: dict[str, bool]) -> tuple[str, str, Event]:
        if not self.db.get_case(case_id):
            raise PolicyError(f"Unknown case: {case_id}")
        target_hash = fingerprint(target)
        stored_purpose = re.sub(
            re.escape(target.strip()), "[TARGET]", lawful_purpose.strip(),
            flags=re.IGNORECASE,
        )
        audit_id, scan_id = str(uuid4()), str(uuid4())
        self.db.start_sensitive_audit(
            audit_id, case_id, workflow, target_hash, stored_purpose, attestations
        )
        self.db.start_spider_scan(scan_id, case_id, "SENSITIVE_TARGET_HASH", target_hash,
                                  f"sensitive:{workflow}")
        seed = Event(
            "SENSITIVE_TARGET_HASH", {"sha256": target_hash}, f"sensitive:{workflow}",
            scan_id, case_id, confidence=100, tags=["redacted-target"],
        )
        self.db.add_spider_event(seed.to_dict())
        return audit_id, scan_id, seed

    def _finish(self, audit_id: str, scan_id: str, seed: Event, workflow: str,
                results: list[dict[str, Any]], status: str = "completed") -> dict[str, Any]:
        for result in results:
            event = child(
                seed, result["event_type"], result["data"], f"sensitive:{workflow}",
                confidence=result.get("confidence", 70), risk=result.get("risk", "info"),
                tags=["sensitive", "redacted", *result.get("tags", [])],
            )
            self.db.add_spider_event(event.to_dict())
        stable_results = sorted(
            results, key=lambda item: json.dumps(item, sort_keys=True, default=str)
        )
        digest = hashlib.sha256(
            json.dumps(stable_results, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        changed = self.db.snapshot(
            seed.case_id, f"sensitive:{workflow}:{seed.data['sha256']}", digest, stable_results
        )
        summary = {
            "workflow": workflow, "results": len(results), "scan_id": scan_id,
            "changed": changed,
        }
        self.db.end_spider_scan(scan_id, status, {"events": len(results) + 1, **summary})
        self.db.end_sensitive_audit(audit_id, status, summary)
        self._preserve_redacted(seed.case_id, workflow, results)
        return {"audit_id": audit_id, "scan_id": scan_id, "status": status,
                "results": len(results), "changed": changed}

    def _preserve_redacted(self, case_id: str, workflow: str,
                           results: list[dict[str, Any]]) -> None:
        with tempfile.TemporaryDirectory(prefix="traceatlas-sensitive-") as temp:
            path = Path(temp) / "redacted-results.json"
            path.write_text(json.dumps({
                "workflow": workflow, "results": results,
            }, indent=2, ensure_ascii=False), encoding="utf-8")
            EvidenceStore(self.workspace, self.db, case_id).preserve_file(
                path, f"sensitive-output:{workflow}:redacted"
            )

    @staticmethod
    def _hibp_headers() -> dict[str, str]:
        key = os.environ.get("HIBP_API_KEY", "")
        if not re.fullmatch(r"[0-9A-Fa-f]{32}", key):
            raise PolicyError("Set a valid 32-character HIBP_API_KEY")
        return {
            "hibp-api-key": key,
            "user-agent": "TraceAtlas-Automator/0.4 (authorized defensive monitoring)",
            "accept": "application/json",
        }

    def darkweb_monitor(self, case_id: str, domain: str, *, lawful_purpose: str,
                        authorized: bool, allow_sensitive: bool,
                        owned_domain: bool, index_file: Path | None,
                        live_ahmia: bool, authorized_feed: bool,
                        source_permission: bool) -> dict[str, Any]:
        validate_target("domain", domain)
        if live_ahmia == (index_file is not None):
            raise PolicyError("Choose exactly one dark-web source: --index-file or --live-ahmia")
        source_authorized = source_permission if live_ahmia else authorized_feed
        attest = {
            "owned_domain": owned_domain, "metadata_only": True,
            "authorized_source": source_authorized,
            "live_ahmia": live_ahmia,
        }
        require_sensitive_policy(
            authorized=authorized, allow_sensitive=allow_sensitive,
            lawful_purpose=lawful_purpose, attestations=attest,
            required=("owned_domain", "metadata_only", "authorized_source"),
        )
        if index_file is not None:
            validate_target("file", str(index_file))
            if index_file.stat().st_size > MAX_RESPONSE:
                raise PolicyError("Dark-web index export exceeds the 2 MiB parsing limit")
            status, body = 200, index_file.read_bytes()
            source_tag = "approved-index-export"
        else:
            url = "https://ahmia.fi/search/?" + urlencode({"q": f'"{domain}"'})
            status, body = self.http_get(url, {"User-Agent": "TraceAtlas-Automator/0.4"}, 20)
            source_tag = "ahmia-index"
        audit, scan, seed = self._begin(case_id, "darkweb-monitor", domain, lawful_purpose, attest)
        if status != 200:
            return self._finish(audit, scan, seed, "darkweb-monitor", [], "partial")
        parser = _AhmiaLinks()
        parser.feed(body.decode("utf-8", errors="replace"))
        unique = {item["service_fingerprint"]: item for item in parser.results}
        results = []
        for item in list(unique.values())[:100]:
            title = re.sub(re.escape(domain), "[TARGET]", item["title"], flags=re.IGNORECASE)
            title = re.sub(r"[a-z2-7]{16,56}\.onion", "[ONION]", title, flags=re.IGNORECASE)
            results.append({
                "event_type": "DARKWEB_INDEX_MENTION",
                "data": {"service_fingerprint": item["service_fingerprint"],
                         "title_sha256": fingerprint(title),
                         "title_length": len(title),
                         "target_mentioned": "[TARGET]" in title},
                "confidence": 50, "risk": "medium",
                "tags": [source_tag, "onion-not-fetched"],
            })
        return self._finish(audit, scan, seed, "darkweb-monitor", results)

    def darkweb_feed(self, case_id: str, domain: str, path: Path, source_type: str, *,
                     lawful_purpose: str, authorized: bool, allow_sensitive: bool,
                     owned_domain: bool, source_permission: bool) -> dict[str, Any]:
        """Reduce an approved threat-platform export to non-content mention metadata."""
        validate_target("domain", domain)
        if source_type not in {"stix", "misp", "opencti", "intelowl", "ail"}:
            raise PolicyError("Unsupported dark-web feed type")
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_ARTIFACT:
            raise PolicyError("Feed export must be a regular file up to 32 MiB")
        attest = {
            "owned_domain": owned_domain, "metadata_only": True,
            "authorized_source": source_permission, "onion_fetch_disabled": True,
        }
        require_sensitive_policy(
            authorized=authorized, allow_sensitive=allow_sensitive,
            lawful_purpose=lawful_purpose, attestations=attest,
            required=("owned_domain", "metadata_only", "authorized_source", "onion_fetch_disabled"),
        )
        try:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix.lower() == ".jsonl":
                data: Any = [json.loads(line) for line in raw_text.splitlines() if line.strip()]
            else:
                data = json.loads(raw_text)
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError("Dark-web feed must be valid JSON or JSONL") from exc
        if isinstance(data, dict):
            for key in ("objects", "events", "results", "data", "items"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
            else:
                data = [data]
        if not isinstance(data, list):
            raise PolicyError("Dark-web feed must contain a record list")
        audit, scan, seed = self._begin(case_id, "darkweb-feed", domain, lawful_purpose, attest)
        results = []
        target = domain.lower()
        for record in data[:5000]:
            serialized = json.dumps(record, sort_keys=True, default=str, ensure_ascii=False)[:200_000]
            lowered = serialized.lower()
            if target not in lowered:
                continue
            results.append({
                "event_type": "DARKWEB_FEED_MENTION",
                "data": {
                    "source_type": source_type,
                    "record_fingerprint": fingerprint(serialized),
                    "target_mentioned": True,
                    "indicator_counts": {
                        "onion": len(re.findall(r"[a-z2-7]{16,56}\.onion", lowered)),
                        "cve": len(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", serialized, re.I)),
                        "sha256": len(re.findall(r"\b[a-f0-9]{64}\b", lowered)),
                    },
                },
                "confidence": 65, "risk": "medium",
                "tags": [f"approved-{source_type}-export", "content-not-retained", "onion-not-fetched"],
            })
        status = "partial" if len(data) > 5000 else "completed"
        return self._finish(audit, scan, seed, "darkweb-feed", results, status)

    def darkweb_misp(self, case_id: str, domain: str, *, lawful_purpose: str,
                     authorized: bool, allow_sensitive: bool, owned_domain: bool,
                     source_permission: bool, publish_timestamp: str = "30d",
                     limit: int = 100) -> dict[str, Any]:
        """Query approved MISP metadata without retaining returned indicator content."""
        validate_target("domain", domain)
        attest = {
            "owned_domain": owned_domain, "metadata_only": True,
            "authorized_source": source_permission, "onion_fetch_disabled": True,
            "attachments_disabled": True,
        }
        require_sensitive_policy(
            authorized=authorized, allow_sensitive=allow_sensitive,
            lawful_purpose=lawful_purpose, attestations=attest,
            required=("owned_domain", "metadata_only", "authorized_source",
                      "onion_fetch_disabled", "attachments_disabled"),
        )
        audit, scan, seed = self._begin(case_id, "darkweb-misp", domain, lawful_purpose, attest)
        source_run_id = str(uuid4())
        started = time.monotonic()
        self.db.start_source_run(
            source_run_id, case_id, "misp", "service", fingerprint(domain)
        )
        try:
            data = ServiceClient.misp(domain, {
                "observable_classification": "domain", "publish_timestamp": publish_timestamp,
                "limit": limit, "page": 1, "to_ids": True,
            })
        except Exception as exc:
            self.db.record_integration_result("misp", "failed", type(exc).__name__)
            self.db.finish_source_run(
                source_run_id, "failed", failure_code=type(exc).__name__.lower(),
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            result = self._finish(audit, scan, seed, "darkweb-misp", [], "partial")
            result["failure_code"] = type(exc).__name__
            result["source_run_id"] = source_run_id
            return result
        if isinstance(data, dict):
            for key in ("Attribute", "attributes", "response", "results", "data", "items"):
                value = data.get(key)
                if isinstance(value, dict) and isinstance(value.get("Attribute"), list):
                    data = value["Attribute"]
                    break
                if isinstance(value, list):
                    data = value
                    break
            else:
                data = [data]
        records = data if isinstance(data, list) else []
        target = domain.lower()
        results: list[dict[str, Any]] = []
        for record in records[:500]:
            serialized = json.dumps(record, sort_keys=True, default=str, ensure_ascii=False)[:200_000]
            lowered = serialized.lower()
            if target not in lowered:
                continue
            results.append({
                "event_type": "DARKWEB_FEED_MENTION",
                "data": {
                    "source_type": "misp-service", "record_fingerprint": fingerprint(serialized),
                    "target_mentioned": True,
                    "indicator_counts": {
                        "onion": len(re.findall(r"[a-z2-7]{16,56}\.onion", lowered)),
                        "cve": len(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", serialized, re.I)),
                        "sha256": len(re.findall(r"\b[a-f0-9]{64}\b", lowered)),
                    },
                },
                "confidence": 70, "risk": "medium",
                "tags": ["approved-misp-service", "content-not-retained", "onion-not-fetched"],
            })
        self.db.record_integration_result("misp", "completed")
        status = "partial" if len(records) > 500 else "completed"
        self.db.finish_source_run(
            source_run_id, status, records_received=len(records),
            records_stored=len(results), duration_ms=int((time.monotonic() - started) * 1000),
        )
        result = self._finish(audit, scan, seed, "darkweb-misp", results, status)
        result["source_run_id"] = source_run_id
        return result

    def breach_catalog(self, case_id: str, domain: str, *, lawful_purpose: str,
                       authorized: bool, allow_sensitive: bool,
                       owned_domain: bool) -> dict[str, Any]:
        validate_target("domain", domain)
        attest = {"owned_domain": owned_domain, "metadata_only": True}
        require_sensitive_policy(
            authorized=authorized, allow_sensitive=allow_sensitive,
            lawful_purpose=lawful_purpose, attestations=attest,
            required=("owned_domain", "metadata_only"),
        )
        audit, scan, seed = self._begin(case_id, "breach-catalog", domain, lawful_purpose, attest)
        url = "https://haveibeenpwned.com/api/v3/breaches?" + urlencode({"Domain": domain})
        status, body = self.http_get(url, {
            "User-Agent": "TraceAtlas-Automator/0.4", "Accept": "application/json"
        }, 20)
        records = _json_or(body, []) if status == 200 else []
        if isinstance(records, dict):
            records = [records]
        results = []
        for record in records[:100]:
            if not isinstance(record, dict):
                continue
            minimized = minimize_breach(record)
            raw_domain = minimized.pop("Domain", None)
            if raw_domain:
                minimized["DomainSHA256"] = fingerprint(str(raw_domain))
            results.append({
                "event_type": "BREACH_METADATA", "data": minimized,
                "confidence": 85 if record.get("IsVerified") else 55,
                "risk": "high" if "Passwords" in record.get("DataClasses", []) else "medium",
            })
        return self._finish(audit, scan, seed, "breach-catalog", results,
                            "completed" if status in {200, 404} else "partial")

    def breach_domain(self, case_id: str, domain: str, *, lawful_purpose: str,
                      authorized: bool, allow_sensitive: bool,
                      owned_domain: bool, hibp_domain_verified: bool) -> dict[str, Any]:
        validate_target("domain", domain)
        attest = {
            "owned_domain": owned_domain,
            "hibp_domain_verified": hibp_domain_verified,
        }
        require_sensitive_policy(
            authorized=authorized, allow_sensitive=allow_sensitive,
            lawful_purpose=lawful_purpose, attestations=attest,
            required=("owned_domain", "hibp_domain_verified"),
        )
        audit, scan, seed = self._begin(case_id, "breach-domain", domain, lawful_purpose, attest)
        status, body = self.http_get(
            f"https://haveibeenpwned.com/api/v3/breachedDomain/{quote(domain)}",
            self._hibp_headers(), 20,
        )
        records = _json_or(body, {}) if status == 200 else {}
        results = []
        if isinstance(records, dict):
            for alias, breaches in list(records.items())[:5000]:
                results.append({
                    "event_type": "BREACHED_ACCOUNT_ALIAS",
                    "data": {"alias_sha256": fingerprint(str(alias)),
                             "breaches": _string_list(breaches, limit=100)},
                    "confidence": 90, "risk": "high",
                })
        return self._finish(audit, scan, seed, "breach-domain", results,
                            "completed" if status in {200, 404} else "partial")

    def breach_account(self, case_id: str, email: str, *, lawful_purpose: str,
                       authorized: bool, allow_sensitive: bool,
                       subject_consent: bool) -> dict[str, Any]:
        validate_target("email", email)
        attest = {"subject_consent": subject_consent, "k_anonymity": True}
        require_sensitive_policy(
            authorized=authorized, allow_sensitive=allow_sensitive,
            lawful_purpose=lawful_purpose, attestations=attest,
            required=("subject_consent", "k_anonymity"),
        )
        audit, scan, seed = self._begin(case_id, "breach-account", email, lawful_purpose, attest)
        email_sha1 = hashlib.sha1(email.strip().lower().encode()).hexdigest().upper()
        status, body = self.http_get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/range/{email_sha1[:6]}",
            self._hibp_headers(), 20,
        )
        rows = _json_or(body, []) if status == 200 else []
        matched: list[str] = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            if str(row.get("hashSuffix", "")).upper() == email_sha1[6:]:
                matched = _string_list(row.get("websites"), limit=100)
                break
        results = [{
            "event_type": "ACCOUNT_BREACH_EXPOSURE",
            "data": {"account_sha256": fingerprint(email), "breaches": matched,
                     "exposed": bool(matched)},
            "confidence": 95, "risk": "high" if matched else "info",
            "tags": ["hibp-k-anonymity"],
        }]
        return self._finish(audit, scan, seed, "breach-account", results,
                            "completed" if status == 200 else "partial")

    def password_hash_check(self, case_id: str, sha1_hash: str, *, lawful_purpose: str,
                            authorized: bool, allow_sensitive: bool,
                            owned_account: bool) -> dict[str, Any]:
        digest = validate_sha1(sha1_hash)
        attest = {"owned_account": owned_account, "no_plaintext_password": True}
        require_sensitive_policy(
            authorized=authorized, allow_sensitive=allow_sensitive,
            lawful_purpose=lawful_purpose, attestations=attest,
            required=("owned_account", "no_plaintext_password"),
        )
        audit, scan, seed = self._begin(case_id, "password-hash-check", digest, lawful_purpose, attest)
        status, body = self.http_get(
            f"https://api.pwnedpasswords.com/range/{digest[:5]}",
            {"User-Agent": "TraceAtlas-Automator/0.4", "Add-Padding": "true"}, 20,
        )
        count = 0
        if status == 200:
            for line in body.decode("utf-8", errors="replace").splitlines():
                suffix, _, raw_count = line.partition(":")
                if suffix.upper() == digest[5:]:
                    count = int(raw_count) if raw_count.isdigit() else 0
                    break
        results = [{
            "event_type": "PASSWORD_HASH_EXPOSURE",
            "data": {"sha1_fingerprint": fingerprint(digest), "exposure_count": count,
                     "exposed": count > 0},
            "confidence": 100, "risk": "critical" if count else "info",
            "tags": ["hibp-k-anonymity", "hash-only"],
        }]
        return self._finish(audit, scan, seed, "password-hash-check", results,
                            "completed" if status == 200 else "partial")

    def person_profile(self, case_id: str, name: str, *, lawful_purpose: str,
                       authorized: bool, allow_sensitive: bool,
                       subject_consent: bool) -> dict[str, Any]:
        name = " ".join(name.split())
        if len(name) < 3 or len(name) > 120:
            raise PolicyError("Person name must be 3-120 characters")
        attest = {"subject_consent": subject_consent, "professional_data_only": True}
        require_sensitive_policy(
            authorized=authorized, allow_sensitive=allow_sensitive,
            lawful_purpose=lawful_purpose, attestations=attest,
            required=("subject_consent", "professional_data_only"),
        )
        audit, scan, seed = self._begin(case_id, "person-profile", name, lawful_purpose, attest)
        results: list[dict[str, Any]] = []
        token = os.environ.get("ORCID_ACCESS_TOKEN")
        if token:
            url = "https://pub.orcid.org/v3.0/search/?" + urlencode({"q": f'"{name}"'})
            status, body = self.http_get(url, {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.orcid+json",
                "User-Agent": "TraceAtlas-Automator/0.4",
            }, 20)
            if status == 200:
                data = _json_or(body, {})
                if not isinstance(data, dict):
                    data = {}
                orcid_results = data.get("result", [])
                if not isinstance(orcid_results, list):
                    orcid_results = []
                for item in orcid_results[:10]:
                    if not isinstance(item, dict):
                        continue
                    identifier = item.get("orcid-identifier", {})
                    if not isinstance(identifier, dict):
                        continue
                    uri = identifier.get("uri")
                    parsed_uri = urlparse(str(uri)) if uri else None
                    if parsed_uri and parsed_uri.scheme == "https" and parsed_uri.hostname == "orcid.org":
                        results.append({
                            "event_type": "PROFESSIONAL_PROFILE_CANDIDATE",
                            "data": {"source": "ORCID", "public_uri": str(uri)[:200],
                                     "match_basis": "name-search"},
                            "confidence": 35, "risk": "info", "tags": ["candidate-not-identity"],
                        })
        crossref_url = "https://api.crossref.org/works?" + urlencode({
            "query.author": name, "rows": "5", "select": "DOI,title,author,published"
        })
        status, body = self.http_get(crossref_url, {
            "User-Agent": "TraceAtlas-Automator/0.4",
            "Accept": "application/json",
        }, 20)
        if status == 200:
            data = _json_or(body, {})
            if not isinstance(data, dict):
                data = {}
            message = data.get("message", {})
            if not isinstance(message, dict):
                message = {}
            crossref_items = message.get("items", [])
            if not isinstance(crossref_items, list):
                crossref_items = []
            for item in crossref_items[:5]:
                if not isinstance(item, dict):
                    continue
                titles = item.get("title")
                title = titles[0] if isinstance(titles, list) and titles else None
                published = item.get("published")
                date_parts = published.get("date-parts") if isinstance(published, dict) else None
                results.append({
                    "event_type": "PUBLICATION_CANDIDATE",
                    "data": {"source": "Crossref", "doi": _optional_text(item.get("DOI"), 160),
                             "title": _optional_text(title, 300),
                             "date_parts": date_parts[:1] if isinstance(date_parts, list) else None},
                    "confidence": 30, "risk": "info", "tags": ["candidate-not-identity"],
                })
        return self._finish(audit, scan, seed, "person-profile", results)

    def wifi_locate(self, case_id: str, bssid: str, *, lawful_purpose: str,
                    authorized: bool, allow_sensitive: bool,
                    owned_asset: bool) -> dict[str, Any]:
        normalized = validate_bssid(bssid)
        attest = {"owned_asset": owned_asset, "coarse_location_only": True}
        require_sensitive_policy(
            authorized=authorized, allow_sensitive=allow_sensitive,
            lawful_purpose=lawful_purpose, attestations=attest,
            required=("owned_asset", "coarse_location_only"),
        )
        name, token = os.environ.get("WIGLE_API_NAME", ""), os.environ.get("WIGLE_API_TOKEN", "")
        if not name or not token:
            raise PolicyError("Set WIGLE_API_NAME and WIGLE_API_TOKEN")
        audit, scan, seed = self._begin(case_id, "wifi-locate", normalized, lawful_purpose, attest)
        auth = base64.b64encode(f"{name}:{token}".encode()).decode()
        url = "https://api.wigle.net/api/v2/network/search?" + urlencode({"netid": normalized})
        status, body = self.http_get(url, {
            "Authorization": f"Basic {auth}", "Accept": "application/json",
            "User-Agent": "TraceAtlas-Automator/0.4",
        }, 20)
        payload = _json_or(body, {}) if status == 200 else {}
        results = []
        wifi_results = payload.get("results", []) if isinstance(payload, dict) else []
        if not isinstance(wifi_results, list):
            wifi_results = []
        for row in wifi_results[:10]:
            if not isinstance(row, dict):
                continue
            lat, lon = row.get("trilat"), row.get("trilong")
            results.append({
                "event_type": "WIFI_COARSE_LOCATION",
                "data": {
                    "bssid_sha256": fingerprint(normalized),
                    "latitude_coarse": _coarse_coordinate(lat, -90, 90),
                    "longitude_coarse": _coarse_coordinate(lon, -180, 180),
                    "country": _optional_text(row.get("country"), 80),
                    "region": _optional_text(row.get("region"), 120),
                    "city": _optional_text(row.get("city"), 120),
                    "last_observed": _optional_text(row.get("lastupdt"), 80),
                    "encryption": _optional_text(row.get("encryption"), 80),
                },
                "confidence": 55, "risk": "medium", "tags": ["approximately-1km", "owned-asset"],
            })
        return self._finish(audit, scan, seed, "wifi-locate", results,
                            "completed" if status in {200, 404} else "partial")

    def breach_artifact(self, case_id: str, path: Path, *, lawful_purpose: str,
                        authorized: bool, allow_sensitive: bool,
                        authorized_data: bool) -> dict[str, Any]:
        validate_target("file", str(path))
        attest = {"authorized_data": authorized_data, "no_raw_copy": True}
        require_sensitive_policy(
            authorized=authorized, allow_sensitive=allow_sensitive,
            lawful_purpose=lawful_purpose, attestations=attest,
            required=("authorized_data", "no_raw_copy"),
        )
        if path.stat().st_size > MAX_ARTIFACT:
            raise PolicyError("Breach artifact exceeds the 32 MiB local-analysis limit")
        suffix = path.suffix.lower()
        rows, columns = 0, set()
        sensitive_columns = set()
        patterns = ("email", "password", "passwd", "phone", "address", "token", "secret", "hash")
        if suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            records = data if isinstance(data, list) else [data]
            rows = len(records)
            for record in records[:10000]:
                if isinstance(record, dict):
                    columns.update(str(key) for key in record)
        elif suffix in {".csv", ".tsv"}:
            with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                reader = csv.DictReader(handle, delimiter="\t" if suffix == ".tsv" else ",")
                columns.update(reader.fieldnames or [])
                for rows, _ in enumerate(reader, start=1):
                    if rows >= 1_000_000:
                        break
        else:
            raise PolicyError("Breach artifact analysis supports JSON, CSV or TSV only")
        for column in columns:
            if any(pattern in column.lower() for pattern in patterns):
                sensitive_columns.add(column)
        result = {
            "event_type": "BREACH_ARTIFACT_SUMMARY",
            "data": {"sha256": sha256_file(path), "size": path.stat().st_size,
                     "rows_sampled": rows, "column_count": len(columns),
                     "columns_sha256": [fingerprint(column) for column in sorted(columns)],
                     "sensitive_column_count": len(sensitive_columns)},
            "confidence": 95, "risk": "high" if sensitive_columns else "medium",
            "tags": ["raw-artifact-not-copied"],
        }
        audit, scan, seed = self._begin(
            case_id, "breach-artifact", str(path), lawful_purpose, attest
        )
        return self._finish(audit, scan, seed, "breach-artifact", [result])
