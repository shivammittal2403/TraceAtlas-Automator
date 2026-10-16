"""Static, evidence-bound cyber employees; no collection or code execution.

Record schemas are intentionally explicit. Indicator sightings, actor aliases,
vendor ranges and test labels are supplied assertions; they are never promoted
to verified source truth, attribution, malware verdicts or exploitability.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit

from .common import AnalysisContext, canonical, digest, identifier, instant, number, text

ATTACK = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,12}\Z")
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
VERDICTS = {"malicious", "benign", "suspicious", "unknown"}
MAX_LINKS = 200
LIMITS = (
    "Only supplied records were analyzed; no remote collection or code execution occurred.",
    "Source labels, collection times and provenance are assertions within one captured input artifact.",
    "Findings require human review and do not independently verify source truth or attribution.",
)


def _bool(value, name):
    if type(value) is not bool:
        raise ValueError(name + " must be a boolean")
    return value


def _list(value, name, maximum=100):
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(name + " must be a bounded array")
    return value


def _strings(value, name, maximum=100, width=512):
    return [text(item, name, maximum=width) for item in _list(value, name, maximum)]


def _hash(value, algorithm="sha256"):
    value = text(value, algorithm, maximum=128)
    if not re.fullmatch(r"[0-9a-fA-F]{" + str(HASH_LENGTHS[algorithm]) + r"}", value):
        raise ValueError(algorithm + " has an invalid digest")
    return value.lower()


def _techniques(value):
    items = _strings(value, "techniques", width=16)
    if any(not ATTACK.fullmatch(item) for item in items):
        raise ValueError("techniques require ATT&CK-shaped technique IDs")
    return sorted(set(items))


def _domain(value):
    value = text(value, "domain", maximum=253)
    value = value[:-1] if value.endswith(".") else value
    if any(character.isspace() for character in value) or any(character in value for character in "/:@?#[]"):
        raise ValueError("domain must be an exact DNS name")
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("domain has invalid IDNA syntax") from exc
    labels = value.split(".")
    if (len(value) > 253 or len(labels) < 2 or re.fullmatch(r"[0-9.]+", value) or
            any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
        raise ValueError("domain has invalid DNS labels")
    return value


def _ip(value):
    value = text(value, "IP address", maximum=64)
    if "%" in value:
        raise ValueError("IP zone identifiers are not supported")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc


def _observable(kind, value):
    kind = text(kind, "indicator type", maximum=16).lower()
    value = text(value, "indicator value", maximum=2048)
    value = value.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    if kind in {"ipv4", "ipv6", "ip"}:
        address = _ip(value)
        normalized_type = "ipv4" if address.version == 4 else "ipv6"
        if kind != "ip" and kind != normalized_type:
            raise ValueError("indicator IP version does not match its type")
        return normalized_type, str(address)
    if kind == "domain":
        return kind, _domain(value)
    if kind in HASH_LENGTHS:
        return kind, _hash(value, kind)
    if kind == "email":
        if value.count("@") != 1:
            raise ValueError("email requires one @")
        local, domain = value.split("@")
        if (not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local) or
                local.startswith(".") or local.endswith(".") or ".." in local):
            raise ValueError("email local part has invalid syntax")
        return kind, local + "@" + _domain(domain)
    if kind == "url":
        value = re.sub(r"^hxxps(?=://)", "https", value, flags=re.I)
        value = re.sub(r"^hxxp(?=://)", "http", value, flags=re.I)
        if any(character.isspace() or ord(character) < 32 for character in value):
            raise ValueError("URL contains whitespace or controls")
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL requires http/https and a host")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("credential-bearing URLs are not accepted")
        host = parsed.hostname
        try:
            address = _ip(host)
        except ValueError:
            host = _domain(host)
        else:
            host = "[" + str(address) + "]" if address.version == 6 else str(address)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("URL port is invalid") from exc
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("URL port is invalid")
        netloc = host + (":" + str(port) if port is not None else "")
        return kind, urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, parsed.fragment))
    raise ValueError("unsupported indicator type")


def _observables(value):
    result = set()
    for item in _list(value, "indicators"):
        if not isinstance(item, dict) or set(item) != {"type", "value"}:
            raise ValueError("indicators require exactly type and value")
        result.add(_observable(item["type"], item["value"]))
    return sorted(result)


def _observable_id(item):
    return "ioc-" + digest(list(item))[:24]


def _invalid(ctx, record, exc):
    ctx.issue(record.record_id, "invalid_record", str(exc))


def _version(value):
    value = text(value, "version", maximum=100)
    if not re.fullmatch(r"[0-9]{1,10}(?:\.[0-9]{1,10}){0,11}", value):
        raise ValueError("version requires numeric dotted components")
    parts = [int(item) for item in value.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _compare(left, right):
    width = max(len(left), len(right))
    a = left + (0,) * (width - len(left))
    b = right + (0,) * (width - len(right))
    return (a > b) - (a < b)


def _applicability(data, product_key):
    product = data.get(product_key)
    affected_product = data.get("affected_product")
    if product is None or affected_product is None:
        return "unknown", "Both exact product labels are required"
    product = text(product, product_key, maximum=256)
    affected_product = text(affected_product, "affected_product", maximum=256)
    if product.strip().casefold() != affected_product.strip().casefold():
        return "product_mismatch", None
    try:
        installed = _version(data.get("installed_version"))
        introduced = _version(data.get("affected_from"))
        fixed = _version(data.get("fixed_version"))
    except ValueError as exc:
        return "unknown", str(exc)
    if _compare(introduced, fixed) >= 0:
        return "unknown", "affected_from must precede fixed_version"
    affected = _compare(installed, introduced) >= 0 and _compare(installed, fixed) < 0
    return ("affected_by_declared_range" if affected else "outside_declared_range"), None


def cybint(ctx: AnalysisContext):
    matrix = []
    failed = 0
    known = {"mfa", "logging", "backups", "patching", "endpoint_protection"}
    for record in ctx.records:
        try:
            data = record.data
            asset = identifier(data.get("asset_id"), "asset_id")
            exposed = _bool(data.get("internet_exposed"), "internet_exposed")
            criticality = data.get("criticality")
            if criticality not in {"low", "medium", "high"}:
                raise ValueError("criticality requires low, medium or high")
            controls = data.get("controls")
            if not isinstance(controls, dict) or set(controls) - known:
                raise ValueError("controls require recognized control names")
            for name, value in controls.items():
                _bool(value, name)
            negatives = sorted(name for name, value in controls.items() if value is False)
            missing = sorted(known - set(controls))
            priority = "review_high" if negatives and (exposed or criticality == "high") else "review_normal"
            item = {"asset_id": asset, "internet_exposed": exposed, "criticality": criticality,
                    "failed_controls": negatives, "missing_controls": missing, "priority": priority,
                    "record_ids": [record.record_id]}
            failed += len(negatives)
            matrix.append(item)
            ctx.finding("cyber_asset_posture", "Supplied asset controls require contextual review.",
                        [record.record_id], {key: value for key, value in item.items() if key != "record_ids"})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    return ctx.output(metrics={"assets": len(matrix), "failed_control_assertions": failed},
                      artifacts={"control_matrix": matrix}, limitations=LIMITS)


def cti(ctx: AnalysisContext):
    support = defaultdict(list)
    reports = 0
    for record in ctx.records:
        try:
            data = record.data
            report_id = identifier(data.get("report_id"), "report_id")
            observables = _observables(data.get("indicators", []))
            techniques = _techniques(data.get("techniques", []))
            if not observables and not techniques:
                raise ValueError("report requires indicators or technique assertions")
            published = instant(data["published_at"], "published_at") if "published_at" in data else None
            expires = instant(data["valid_until"], "valid_until") if "valid_until" in data else None
            if published and expires and expires < published:
                raise ValueError("valid_until precedes published_at")
            verdict = data.get("verdict", "unknown")
            if verdict not in VERDICTS:
                raise ValueError("verdict has an unknown value")
            temporal = "future_dated" if published and published > ctx.as_of else (
                "expired" if expires and expires <= ctx.as_of else "current")
            if temporal != "current":
                ctx.issue(record.record_id, temporal + "_report", "Report temporal bounds require review.")
            source = ctx.sources[record.source_id]
            origin = source.get("original_source_id", record.source_id)
            for item in observables:
                support[item].append({"record_id": record.record_id, "source_id": record.source_id,
                                      "declared_origin_id": origin, "temporal_status": temporal,
                                      "verdict": verdict})
            reports += 1
            ctx.finding("threat_report", "Supplied threat report assertions were normalized.",
                        [record.record_id], {"report_id": report_id, "indicator_count": len(observables),
                                             "technique_ids": techniques, "temporal_status": temporal,
                                             "verdict": verdict, "independence_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    indicators = []
    for (kind, value), sightings in sorted(support.items()):
        indicators.append({"indicator_type": kind, "value": value,
                           "record_ids": sorted({item["record_id"] for item in sightings}),
                           "declared_origin_count": len({item["declared_origin_id"] for item in sightings}),
                           "current_record_ids": sorted(item["record_id"] for item in sightings if item["temporal_status"] == "current"),
                           "independence_verified": False})
    if len(indicators) > MAX_LINKS:
        ctx.issue(None, "artifact_truncated", "Indicator support artifact is limited to 200 entries.")
    return ctx.output(metrics={"reports": reports, "unique_indicators": len(indicators)},
                      artifacts={"indicator_support": indicators[:MAX_LINKS]}, limitations=LIMITS)


def iocint(ctx: AnalysisContext):
    grouped = defaultdict(list)
    for record in ctx.records:
        try:
            data = record.data
            item = _observable(data.get("indicator_type"), data.get("value"))
            verdict = data.get("verdict", "unknown")
            if verdict not in VERDICTS:
                raise ValueError("verdict has an unknown value")
            first = instant(data["first_seen"], "first_seen") if "first_seen" in data else None
            last = instant(data["last_seen"], "last_seen") if "last_seen" in data else None
            expires = instant(data["expires_at"], "expires_at") if "expires_at" in data else None
            if first and last and first > last:
                raise ValueError("first_seen is after last_seen")
            expired = expires is not None and expires <= ctx.as_of
            if expired:
                ctx.issue(record.record_id, "expired_indicator", "Indicator expired at or before as_of.")
            grouped[item].append((record, verdict, expired))
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    indicators = []
    for (kind, value), rows in sorted(grouped.items()):
        verdicts = sorted({row[1] for row in rows})
        conflicting = "benign" in verdicts and ("malicious" in verdicts or "suspicious" in verdicts)
        item = {"indicator_type": kind, "value": value, "record_ids": sorted(row[0].record_id for row in rows),
                "verdicts": verdicts, "conflicting_verdicts": conflicting,
                "active_record_ids": sorted(row[0].record_id for row in rows if not row[2])}
        if kind in {"ipv4", "ipv6"}:
            address = _ip(value)
            item["ip_scope"] = "global" if address.is_global else "non_global"
        indicators.append(item)
        ctx.finding("indicator_correlation", "Observable sightings retain their supplied verdicts and expiry.",
                    item["record_ids"], {key: value for key, value in item.items() if key != "record_ids"})
    if len(indicators) > MAX_LINKS:
        ctx.issue(None, "artifact_truncated", "Indicator artifact is limited to 200 entries.")
    return ctx.output(metrics={"unique_indicators": len(indicators),
                               "valid_sightings": sum(len(rows) for rows in grouped.values()),
                               "conflicts": sum(item["conflicting_verdicts"] for item in indicators)},
                      artifacts={"indicators": indicators[:MAX_LINKS]}, limitations=LIMITS)


def ttpint(ctx: AnalysisContext):
    versions = Counter()
    procedures = 0
    for record in ctx.records:
        try:
            data = record.data
            technique = text(data.get("technique_id"), "technique_id", maximum=16)
            if not ATTACK.fullmatch(technique):
                raise ValueError("technique_id requires an ATT&CK-shaped ID")
            procedure = text(data.get("procedure"), "procedure", maximum=3000)
            version = text(data["attack_version"], "attack_version", maximum=32) if "attack_version" in data else None
            if version is None:
                ctx.issue(record.record_id, "unversioned_mapping", "ATT&CK release was not supplied.")
            versions[version or "unspecified"] += 1
            procedures += 1
            ctx.finding("technique_procedure", "Supplied procedure supports review of a declared technique mapping.",
                        [record.record_id], {"technique_id": technique, "procedure": procedure,
                                             "attack_version": version, "mapping_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    return ctx.output(metrics={"procedures": procedures, "declared_versions": dict(sorted(versions.items()))},
                      limitations=LIMITS + ("Technique syntax is checked; no ATT&CK knowledge base was fetched.",))

def threatactorint(ctx: AnalysisContext):
    actors = []
    for record in ctx.records:
        try:
            data = record.data
            provider = text(data.get("provider"), "provider", maximum=256)
            label = text(data.get("actor_label"), "actor_label", maximum=256)
            aliases = sorted(set(_strings(data.get("aliases", []), "aliases", width=256)))
            indicators = _observables(data.get("indicators", []))
            techniques = _techniques(data.get("techniques", []))
            item = {"record_id": record.record_id, "provider": provider, "actor_label": label,
                    "aliases": aliases, "indicators": set(indicators)}
            actors.append(item)
            ctx.finding("actor_label_assertion", "Provider-scoped actor labels and aliases remain unverified assertions.",
                        [record.record_id], {"provider": provider, "actor_label": label, "aliases": aliases,
                                             "indicator_count": len(indicators), "technique_ids": techniques,
                                             "attribution_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    links = []
    count = 0
    for index, left in enumerate(actors):
        for right in actors[index + 1:]:
            if (left["provider"], left["actor_label"]) == (right["provider"], right["actor_label"]):
                continue
            shared = sorted(left["indicators"] & right["indicators"])
            if not shared:
                continue
            count += 1
            if len(links) < MAX_LINKS:
                links.append({"record_ids": sorted([left["record_id"], right["record_id"]]),
                              "left": {"provider": left["provider"], "actor_label": left["actor_label"]},
                              "right": {"provider": right["provider"], "actor_label": right["actor_label"]},
                              "shared_indicator_ids": [_observable_id(item) for item in shared],
                              "candidate_only": True, "attribution_verified": False,
                              "alternative_explanations": ["shared infrastructure", "copied reporting", "nonexclusive tooling"],
                              "falsification": "Check independent original evidence and whether shared observables are exclusive."})
    if count > MAX_LINKS:
        ctx.issue(None, "artifact_truncated", "Actor candidate links are limited to 200 entries.")
    return ctx.output(metrics={"actor_label_assertions": len(actors), "candidate_links": count},
                      artifacts={"candidate_links": links}, limitations=LIMITS)


def campaignint(ctx: AnalysisContext):
    campaigns = []
    counts = Counter()
    for record in ctx.records:
        try:
            data = record.data
            campaign = identifier(data.get("campaign_id"), "campaign_id")
            start = instant(data.get("start_at"), "start_at")
            end = instant(data.get("end_at"), "end_at")
            if start > end:
                raise ValueError("campaign start_at is after end_at")
            indicators = _observables(data.get("indicators", []))
            techniques = _techniques(data.get("techniques", []))
            campaigns.append({"record_id": record.record_id, "campaign_id": campaign, "start": start, "end": end,
                              "indicators": set(indicators), "techniques": set(techniques)})
            counts[campaign] += 1
            if start > ctx.as_of or end > ctx.as_of:
                ctx.issue(record.record_id, "future_campaign_window", "Campaign interval extends beyond as_of.")
            ctx.finding("campaign_window", "Supplied campaign interval and declared observables were normalized.",
                        [record.record_id], {"campaign_id": campaign, "start_at": start.isoformat(),
                                             "end_at": end.isoformat(), "indicator_count": len(indicators),
                                             "technique_ids": techniques, "attribution_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    for item in campaigns:
        if counts[item["campaign_id"]] > 1:
            ctx.issue(item["record_id"], "duplicate_campaign_id", "Multiple supplied records assert this campaign ID.")
    links = []
    count = 0
    for index, left in enumerate(campaigns):
        for right in campaigns[index + 1:]:
            if left["campaign_id"] == right["campaign_id"]:
                continue
            start = max(left["start"], right["start"])
            end = min(left["end"], right["end"])
            shared_indicators = sorted(left["indicators"] & right["indicators"])
            shared_techniques = sorted(left["techniques"] & right["techniques"])
            if start > end or not (shared_indicators or shared_techniques):
                continue
            count += 1
            if len(links) < MAX_LINKS:
                links.append({"record_ids": sorted([left["record_id"], right["record_id"]]),
                              "campaign_ids": [left["campaign_id"], right["campaign_id"]],
                              "overlap_start": start.isoformat(), "overlap_end": end.isoformat(),
                              "shared_indicator_ids": [_observable_id(item) for item in shared_indicators],
                              "shared_technique_ids": shared_techniques, "candidate_only": True,
                              "basis": "overlapping supplied windows and shared assertions",
                              "falsification": "Resolve original sources, common tooling and incompatible event details."})
    if count > MAX_LINKS:
        ctx.issue(None, "artifact_truncated", "Campaign candidate links are limited to 200 entries.")
    return ctx.output(metrics={"campaign_records": len(campaigns), "candidate_links": count},
                      artifacts={"candidate_links": links}, limitations=LIMITS)


def malint(ctx: AnalysisContext):
    profiles = 0
    hint_counts = Counter()
    imports_map = {
        "memory_access": {"writeprocessmemory", "readprocessmemory", "virtualallocex", "createremotethread"},
        "networking": {"internetopen", "internetopenw", "internetopena", "connect", "winhttpopen", "wsastartup"},
        "registry_access": {"regsetvalueexw", "regsetvalueexa", "regcreatekeyexw", "regopenkeyexw"},
        "cryptography": {"cryptencrypt", "cryptdecrypt", "bcryptencrypt", "bcryptdecrypt"},
    }
    for record in ctx.records:
        try:
            data = record.data
            name = text(data.get("file_name"), "file_name", maximum=512)
            size = data.get("file_size")
            if type(size) is not int or not 0 <= size <= 10 ** 15:
                raise ValueError("file_size requires a bounded nonnegative integer")
            supplied_hashes = data.get("hashes")
            if not isinstance(supplied_hashes, dict) or not supplied_hashes or set(supplied_hashes) - set(HASH_LENGTHS):
                raise ValueError("hashes require md5, sha1 or sha256")
            hashes = {algorithm: _hash(value, algorithm) for algorithm, value in sorted(supplied_hashes.items())}
            imports = _strings(data.get("imports", []), "imports", width=256)
            strings = _strings(data.get("strings", []), "strings", width=2048)
            signature = data.get("signature")
            signature_assertion = None
            signer = None
            if signature is not None:
                if not isinstance(signature, dict) or set(signature) - {"verified", "signer"}:
                    raise ValueError("signature requires verified and optional signer")
                signature_assertion = _bool(signature.get("verified"), "signature.verified")
                signer = text(signature["signer"], "signer", maximum=256) if "signer" in signature else None
            normalized_imports = {item.rsplit("!", 1)[-1].casefold() for item in imports}
            hints = sorted(label for label, names in imports_map.items() if normalized_imports & names)
            string_markers = sorted({
                marker for marker, pattern in {
                    "powershell_encoded_command": r"(?i)\bpowershell(?:\.exe)?\b.{0,100}-(?:enc|encodedcommand)\b",
                    "http_literal": r"(?i)https?://",
                    "registry_run_key_literal": r"(?i)software\\microsoft\\windows\\currentversion\\run",
                }.items() if any(re.search(pattern, item) for item in strings)
            })
            hint_counts.update(hints)
            profiles += 1
            ctx.finding("static_file_profile", "Supplied static metadata yields review hints without a malware verdict.",
                        [record.record_id], {"file_name": name, "file_size": size, "hashes": hashes,
                                             "capability_hints": hints, "string_markers": string_markers,
                                             "signature_verification_asserted": signature_assertion, "signer": signer,
                                             "content_hash_verified": False, "malware_verdict": "not_determined"})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    return ctx.output(metrics={"file_profiles": profiles, "capability_hint_counts": dict(sorted(hint_counts.items()))},
                      limitations=LIMITS + ("Import and string hints also occur in legitimate software; no binary bytes were inspected.",))


def exploitint(ctx: AnalysisContext):
    analyzed = 0
    poc = 0
    reported = 0
    for record in ctx.records:
        try:
            data = record.data
            cve = text(data.get("cve_id"), "cve_id", maximum=40)
            if not CVE.fullmatch(cve):
                raise ValueError("cve_id has invalid syntax")
            public_poc = _bool(data["public_poc"], "public_poc") if "public_poc" in data else None
            exploitation = _bool(data["exploitation_reported"], "exploitation_reported") if "exploitation_reported" in data else None
            applicability, reason = _applicability(data, "asset_product")
            if reason:
                ctx.issue(record.record_id, "applicability_unresolved", reason)
            analyzed += 1
            poc += public_poc is True
            reported += exploitation is True
            ctx.finding("exploit_report", "PoC and exploitation reports remain separate from asset applicability.",
                        [record.record_id], {"cve_id": cve, "public_poc_asserted": public_poc,
                                             "exploitation_reported_asserted": exploitation,
                                             "applicability": applicability, "exploitability": "not_determined",
                                             "report_authenticity_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    return ctx.output(metrics={"reports": analyzed, "public_poc_assertions": poc,
                               "exploitation_assertions": reported},
                      limitations=LIMITS + ("No PoC was retrieved, executed or validated against any asset.",))


def vulnint(ctx: AnalysisContext):
    counts = Counter()
    for record in ctx.records:
        try:
            data = record.data
            asset = identifier(data.get("asset_id"), "asset_id")
            product = text(data.get("product"), "product", maximum=256)
            cve = text(data.get("cve_id"), "cve_id", maximum=40)
            if not CVE.fullmatch(cve):
                raise ValueError("cve_id has invalid syntax")
            applicability, reason = _applicability(data, "product")
            if reason:
                ctx.issue(record.record_id, "applicability_unresolved", reason)
            counts[applicability] += 1
            ctx.finding("vulnerability_applicability", "Exact product labels and declared numeric version bounds were compared.",
                        [record.record_id], {"asset_id": asset, "product": product, "cve_id": cve,
                                             "applicability": applicability, "range_source_verified": False,
                                             "lower_bound_inclusive": True, "fixed_bound_exclusive": True,
                                             "exploitability": "not_determined"})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    return ctx.output(metrics={"asset_advisories": sum(counts.values()), "applicability_counts": dict(sorted(counts.items()))},
                      limitations=LIMITS + ("Only supplied numeric dotted ranges are compared; vendor build semantics and advisory authenticity remain unresolved.",))


def incidentint(ctx: AnalysisContext):
    incidents = defaultdict(list)
    for record in ctx.records:
        try:
            data = record.data
            incident = identifier(data.get("incident_id"), "incident_id")
            event_id = identifier(data.get("event_id"), "event_id")
            event_type = identifier(data.get("event_type"), "event_type")
            when = instant(data.get("timestamp"), "timestamp")
            asset = identifier(data["asset_id"], "asset_id") if "asset_id" in data else None
            description = text(data["description"], "description", maximum=1000) if "description" in data else None
            if when > ctx.as_of:
                ctx.issue(record.record_id, "future_event", "Event timestamp is after as_of.")
            incidents[incident].append({"record_id": record.record_id, "event_id": event_id, "event_type": event_type,
                                        "timestamp": when.isoformat(), "asset_id": asset, "description": description})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    timelines = []
    for incident, events in sorted(incidents.items()):
        events.sort(key=lambda item: (item["timestamp"], item["event_id"], item["record_id"]))
        by_id = defaultdict(list)
        for event in events:
            by_id[event["event_id"]].append(event)
        conflicts = []
        for event_id, duplicates in sorted(by_id.items()):
            if len(duplicates) > 1:
                signatures = {canonical({key: value for key, value in item.items() if key != "record_id"}) for item in duplicates}
                conflict = len(signatures) > 1
                if conflict:
                    conflicts.append(event_id)
                for item in duplicates:
                    ctx.issue(item["record_id"], "conflicting_event_id" if conflict else "duplicate_event_id",
                              "Duplicate event assertions are preserved for review.")
        timeline = {"incident_id": incident, "events": events, "conflicting_event_ids": conflicts}
        timelines.append(timeline)
        ctx.finding("incident_timeline", "Supplied incident events were ordered without discarding duplicates.",
                    [item["record_id"] for item in events],
                    {"incident_id": incident, "event_count": len(events), "first_at": events[0]["timestamp"],
                     "last_at": events[-1]["timestamp"], "conflicting_event_ids": conflicts,
                     "event_type_counts": dict(sorted(Counter(item["event_type"] for item in events).items()))})
    return ctx.output(metrics={"incidents": len(timelines), "events": sum(len(items) for items in incidents.values())},
                      artifacts={"timelines": timelines}, limitations=LIMITS)

_APACHE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] "(?P<method>[A-Z]+) [^"\r\n]* HTTP/[0-9.]+" (?P<status>[0-9]{3}) (?:[0-9]+|-)(?: ".*")?\Z'
)
_MONTHS = {name: index for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


def _apache_timestamp(value):
    match = re.fullmatch(r"([0-9]{2})/([A-Za-z]{3})/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+-])([0-9]{2})([0-9]{2})", value)
    if not match or match[2] not in _MONTHS:
        raise ValueError("Apache timestamp has invalid syntax")
    hour_offset, minute_offset = int(match[8]), int(match[9])
    if hour_offset > 23 or minute_offset > 59:
        raise ValueError("Apache timezone offset is invalid")
    offset = timedelta(hours=hour_offset, minutes=minute_offset)
    if match[7] == "-":
        offset = -offset
    return datetime(int(match[3]), _MONTHS[match[2]], int(match[1]), int(match[4]),
                    int(match[5]), int(match[6]), tzinfo=timezone(offset)).astimezone(timezone.utc)


def _json_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("JSON log contains duplicate keys")
        result[key] = value
    return result


def _bad_json_constant(value):
    raise ValueError("JSON log contains a nonfinite constant")


def _event(value):
    if not isinstance(value, dict):
        raise ValueError("log event must be an object")
    when = instant(value.get("timestamp"), "event timestamp")
    event_type = identifier(value.get("event_type"), "event_type")
    source_ip = str(_ip(value["src_ip"])) if "src_ip" in value else None
    account = text(value["account"], "account", maximum=256) if "account" in value else None
    outcome = value.get("outcome", "unknown")
    if outcome not in {"success", "failure", "unknown"}:
        raise ValueError("outcome requires success, failure or unknown")
    status = value.get("status_code")
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        raise ValueError("status_code requires an integer from 100 through 599")
    return {"timestamp": when.isoformat(), "event_type": event_type, "src_ip": source_ip,
            "account": account, "outcome": outcome, "status_code": status}


def logint(ctx: AnalysisContext):
    threshold = ctx.parameters.get("failure_threshold", 3)
    if type(threshold) is not int or not 2 <= threshold <= 100:
        raise ValueError("failure_threshold requires an integer from 2 through 100")
    events = []
    failures = defaultdict(list)
    for record in ctx.records:
        try:
            data = record.data
            format_name = data.get("format")
            if format_name == "structured":
                event = _event(data.get("event"))
            elif format_name == "json":
                raw = text(data.get("line"), "log line", maximum=16384)
                event = _event(json.loads(raw, object_pairs_hook=_json_pairs,
                                         parse_constant=_bad_json_constant,
                                         parse_float=lambda value: number(float(value), "JSON number")))
            elif format_name == "apache":
                raw = text(data.get("line"), "log line", maximum=16384)
                match = _APACHE.fullmatch(raw)
                if not match:
                    raise ValueError("log line is not supported Apache common/combined format")
                status = int(match["status"])
                if not 100 <= status <= 599:
                    raise ValueError("Apache status code is outside 100 through 599")
                event = {"timestamp": _apache_timestamp(match["date"]).isoformat(),
                         "event_type": "http_request", "src_ip": str(_ip(match["ip"])),
                         "account": None, "outcome": "unknown", "status_code": status}
            else:
                raise ValueError("format requires structured, json or apache")
            event["record_id"] = record.record_id
            if instant(event["timestamp"]) > ctx.as_of:
                ctx.issue(record.record_id, "future_event", "Log event timestamp is after as_of.")
            events.append(event)
            if event["outcome"] == "failure" and event["event_type"].casefold() in {
                    "authentication", "login", "auth", "logon", "authentication_failure", "login_failed"}:
                if event["account"] is None and event["src_ip"] is None:
                    ctx.issue(record.record_id, "unattributed_authentication_failure", "Failure lacks account and source IP grouping fields.")
                else:
                    failures[(event["account"], event["src_ip"])].append(event)
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            _invalid(ctx, record, exc)
    events.sort(key=lambda item: (item["timestamp"], item["record_id"]))
    clusters = []
    for key, rows in sorted(failures.items(), key=lambda item: (item[0][0] or "", item[0][1] or "")):
        if len(rows) < threshold:
            continue
        item = {"account": key[0], "src_ip": key[1], "failure_count": len(rows),
                "record_ids": sorted(row["record_id"] for row in rows),
                "first_at": min(row["timestamp"] for row in rows), "last_at": max(row["timestamp"] for row in rows),
                "compromise_verified": False}
        clusters.append(item)
    if events:
        ctx.finding("log_analysis", "Supplied log records were normalized into an explicitly timed event set.",
                    [item["record_id"] for item in events],
                    {"parsed_events": len(events), "authentication_failure_clusters": len(clusters),
                     "event_type_counts": dict(sorted(Counter(item["event_type"] for item in events).items()))})
    for item in clusters[:MAX_LINKS]:
        ctx.finding("authentication_failure_cluster", "Repeated supplied authentication failures warrant review.",
                    item["record_ids"], {key: value for key, value in item.items() if key != "record_ids"})
    if len(clusters) > MAX_LINKS:
        ctx.issue(None, "artifact_truncated", "Authentication failure clusters are limited to 200 entries.")
    return ctx.output(metrics={"parsed_events": len(events), "authentication_failure_clusters": len(clusters),
                               "failure_threshold": threshold},
                      artifacts={"events": events, "authentication_failure_clusters": clusters[:MAX_LINKS]},
                      limitations=LIMITS + ("Clusters have no automatic compromise verdict and no inferred authentication success.",))


def dfirint(ctx: AnalysisContext):
    count = 0
    flags_count = Counter()
    seen = defaultdict(list)
    for record in ctx.records:
        try:
            data = record.data
            artifact = identifier(data.get("artifact_id"), "artifact_id")
            sha256 = _hash(data.get("sha256"))
            claimed = _hash(data["claimed_sha256"]) if "claimed_sha256" in data else None
            path = text(data["path"], "path", maximum=1024) if "path" in data else None
            size = data.get("size_bytes")
            if size is not None and (type(size) is not int or not 0 <= size <= 10 ** 15):
                raise ValueError("size_bytes requires a bounded nonnegative integer")
            supplied = data.get("timestamps")
            if not isinstance(supplied, dict) or not supplied or set(supplied) - {"created", "modified", "accessed", "collected"}:
                raise ValueError("timestamps require created, modified, accessed or collected")
            times = {name: instant(value, name) for name, value in supplied.items()}
            flags = []
            if "created" in times and "modified" in times and times["modified"] < times["created"]:
                flags.append("modified_before_created")
            if "collected" in times and any(value > times["collected"] for name, value in times.items() if name != "collected"):
                flags.append("metadata_after_collection")
            if any(value > ctx.as_of for value in times.values()):
                flags.append("future_timestamp")
            if claimed is not None and claimed != sha256:
                flags.append("declared_hash_mismatch")
            for flag in flags:
                ctx.issue(record.record_id, flag, "Supplied forensic metadata requires clock, copy or provenance review.")
            flags_count.update(flags)
            seen[artifact].append(record.record_id)
            count += 1
            ctx.finding("forensic_artifact_metadata", "Supplied artifact digests and clock relationships were checked.",
                        [record.record_id], {"artifact_id": artifact, "sha256": sha256, "path": path, "size_bytes": size,
                                             "timestamps": {key: value.isoformat() for key, value in sorted(times.items())},
                                             "chronology_flags": flags, "declared_hash_agrees": None if claimed is None else claimed == sha256,
                                             "content_verified": False})
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    for refs in seen.values():
        if len(refs) > 1:
            for ref in refs:
                ctx.issue(ref, "duplicate_artifact_id", "Duplicate artifact IDs remain separate metadata assertions.")
    return ctx.output(metrics={"artifacts": count, "review_flags": dict(sorted(flags_count.items()))},
                      limitations=LIMITS + ("Paths are labels only; no file was opened, hashed or executed.",))


def _flat_fields(value, name, nonempty=False):
    if not isinstance(value, dict) or len(value) > 100 or nonempty and not value:
        raise ValueError(name + " requires a bounded flat object")
    result = {}
    for key, item in value.items():
        identifier(key, name + " field")
        if item is not None and type(item) not in (str, bool, int, float):
            raise ValueError(name + " requires scalar values")
        if type(item) is str:
            text(item, name + " value", maximum=1024)
        if type(item) in (int, float):
            number(item, name + " value")
        result[key] = item
    return result


def _matches(selector, fields):
    return all(key in fields and type(fields[key]) is type(value) and fields[key] == value
               for key, value in selector.items())


def huntint(ctx: AnalysisContext):
    hypotheses = []
    events = []
    for record in ctx.records:
        try:
            data = record.data
            record_type = data.get("record_type")
            if record_type == "hypothesis":
                hypothesis = identifier(data.get("hypothesis_id"), "hypothesis_id")
                description = text(data.get("description"), "description", maximum=2000)
                selector = _flat_fields(data.get("selector"), "selector", True)
                counter = _flat_fields(data["counter_selector"], "counter_selector", True) if "counter_selector" in data else None
                hypotheses.append({"record_id": record.record_id, "hypothesis_id": hypothesis,
                                   "description": description, "selector": selector, "counter": counter})
            elif record_type == "event":
                event_id = identifier(data.get("event_id"), "event_id")
                fields = _flat_fields(data.get("fields"), "fields")
                events.append({"record_id": record.record_id, "event_id": event_id, "fields": fields})
            else:
                raise ValueError("record_type requires hypothesis or event")
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    event_counts = Counter(item["event_id"] for item in events)
    for event in events:
        if event_counts[event["event_id"]] > 1:
            ctx.issue(event["record_id"], "duplicate_event_id", "Event ID has multiple supplied records; counts describe rows, not independent events.")
    statuses = Counter()
    for hypothesis in hypotheses:
        supporting = [event["record_id"] for event in events if _matches(hypothesis["selector"], event["fields"])]
        refuting = [event["record_id"] for event in events if hypothesis["counter"] is not None and _matches(hypothesis["counter"], event["fields"])]
        status = ("untested" if not events else "mixed" if supporting and refuting else
                  "supported_in_sample" if supporting else "contradicted_in_sample" if refuting else
                  "no_support_in_supplied_events")
        statuses[status] += 1
        ctx.finding("hunt_hypothesis", "Declared support and counterexample selectors were evaluated against supplied events.",
                    [hypothesis["record_id"]] + supporting + refuting,
                    {"hypothesis_id": hypothesis["hypothesis_id"], "description": hypothesis["description"],
                     "status": status, "support_record_ids": supporting, "counter_record_ids": refuting,
                     "evaluated_event_rows": len(events), "hypothesis_verified": False})
    if not hypotheses:
        ctx.issue(None, "missing_hypothesis", "No valid hypothesis selectors were supplied.")
    return ctx.output(metrics={"hypotheses": len(hypotheses), "event_rows": len(events),
                               "status_counts": dict(sorted(statuses.items()))},
                      limitations=LIMITS + ("Exact, type-sensitive field matching is a local sample test; no query language was executed.",))


def detectionint(ctx: AnalysisContext):
    rules = []
    events = []
    for record in ctx.records:
        try:
            data = record.data
            record_type = data.get("record_type")
            if record_type == "rule":
                rule_id = identifier(data.get("rule_id"), "rule_id")
                selector = _flat_fields(data.get("selector"), "selector", True)
                enabled = _bool(data.get("enabled"), "enabled")
                techniques = _techniques(data.get("techniques", []))
                rules.append({"record_id": record.record_id, "rule_id": rule_id, "selector": selector,
                              "enabled": enabled, "techniques": techniques})
            elif record_type == "test_event":
                event_id = identifier(data.get("event_id"), "event_id")
                fields = _flat_fields(data.get("fields"), "fields")
                expected = {identifier(item, "expected rule_id") for item in _list(data.get("expected_rule_ids"), "expected_rule_ids")}
                events.append({"record_id": record.record_id, "event_id": event_id,
                               "fields": fields, "expected": expected})
            else:
                raise ValueError("record_type requires rule or test_event")
        except (ValueError, TypeError) as exc:
            _invalid(ctx, record, exc)
    counts = Counter(item["rule_id"] for item in rules)
    for rule in rules:
        if counts[rule["rule_id"]] > 1:
            ctx.issue(rule["record_id"], "ambiguous_rule_id", "Duplicate rule ID is excluded rather than silently selecting a definition.")
    rules = [item for item in rules if counts[item["rule_id"]] == 1]
    known = {item["rule_id"] for item in rules}
    event_counts = Counter(item["event_id"] for item in events)
    for event in events:
        if event_counts[event["event_id"]] > 1:
            ctx.issue(event["record_id"], "duplicate_event_id", "Test event ID has multiple supplied rows; metrics count rows.")
        unknown = sorted(event["expected"] - known)
        if unknown:
            ctx.issue(event["record_id"], "unknown_expected_rule", "Expected rule IDs are unknown or ambiguous: " + ", ".join(unknown)[:2000])
    coverage = defaultdict(list)
    evaluations = []
    for rule in rules:
        confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        fired = []
        expected = []
        mismatches = []
        for event in events:
            matched = rule["enabled"] and _matches(rule["selector"], event["fields"])
            wanted = rule["rule_id"] in event["expected"]
            confusion["tp" if matched and wanted else "fp" if matched else "fn" if wanted else "tn"] += 1
            if matched:
                fired.append(event["record_id"])
            if wanted:
                expected.append(event["record_id"])
            if matched != wanted:
                mismatches.append(event["record_id"])
        if rule["enabled"]:
            for technique in rule["techniques"]:
                coverage[technique].append(rule["rule_id"])
        item = {"rule_id": rule["rule_id"], "enabled": rule["enabled"], "confusion": confusion,
                "fired_record_ids": fired, "expected_record_ids": expected, "mismatch_record_ids": mismatches,
                "technique_ids": rule["techniques"], "coverage_verified": False}
        evaluations.append(item)
        ctx.finding("detection_rule_evaluation", "Declarative exact-field rule was evaluated against supplied test labels.",
                    [rule["record_id"]] + [event["record_id"] for event in events], item)
    if not rules:
        ctx.issue(None, "missing_rule", "No unambiguous valid rule definitions were supplied.")
    if not events:
        ctx.issue(None, "missing_test_events", "No valid labeled test events were supplied; no performance is established.")
    return ctx.output(metrics={"rules": len(rules), "test_event_rows": len(events),
                               "enabled_rules": sum(rule["enabled"] for rule in rules)},
                      artifacts={"coverage": [{"technique_id": key, "rule_ids": sorted(value),
                                                "mapping_verified": False} for key, value in sorted(coverage.items())]},
                      limitations=LIMITS + ("Coverage labels and expected test labels are assertions; Sigma, YARA and scripts are never executed.",))


HANDLERS = {
    "CYBINT": cybint,
    "CTI": cti,
    "IOCINT": iocint,
    "TTPINT": ttpint,
    "THREATACTORINT": threatactorint,
    "CAMPAIGNINT": campaignint,
    "MALINT": malint,
    "EXPLOITINT": exploitint,
    "VULNINT": vulnint,
    "INCIDENTINT": incidentint,
    "LOGINT": logint,
    "DFIRINT": dfirint,
    "HUNTINT": huntint,
    "DETECTIONINT": detectionint,
}
