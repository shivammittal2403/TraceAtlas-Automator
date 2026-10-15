"""Network and RF employees: analyze supplied inventories and observations only.

No handler opens a socket, captures traffic, changes configuration or executes a
command. Routing, ownership and radio-emitter identities remain source assertions.
RPKI semantics: https://www.rfc-editor.org/rfc/rfc6811.html
TLS versions: https://www.rfc-editor.org/rfc/rfc8996.html
SPF static limits: https://www.rfc-editor.org/rfc/rfc7208.html
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, time, timezone
import ipaddress
import math
import re
from urllib.parse import urlsplit

from .common import AnalysisContext, instant, number, text


def _s(value):
    return value.strip() if isinstance(value, str) else ""


def _domain(value):
    value = text(value, "domain", maximum=253).strip().rstrip(".")
    value = value.encode("idna").decode("ascii").lower()
    if len(value) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
        for part in value.split(".")
    ):
        raise ValueError("Invalid DNS name")
    return value


def _asn(value):
    if isinstance(value, str) and re.fullmatch(r"(?:AS)?\d+", value, re.I):
        value = int(re.sub(r"^AS", "", value, flags=re.I))
    if type(value) is not int or not 0 <= value <= 4294967295:
        raise ValueError("ASN requires an unsigned 32-bit integer")
    return value


def _ip(value):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Unscoped IP literal required")
    return ipaddress.ip_address(value)


def _net(value):
    if not isinstance(value, str) or "/" not in value or "%" in value:
        raise ValueError("Explicit CIDR prefix required")
    return ipaddress.ip_network(value, strict=True)


def _date(value):
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return datetime.combine(datetime.fromisoformat(value).date(), time(), timezone.utc)
    return instant(value)


def _array(data, key):
    values = data.get(key)
    if not isinstance(values, list):
        raise ValueError(key + " requires an array")
    return values


def _optional(data, key):
    values = data.get(key, [])
    if not isinstance(values, list):
        raise ValueError(key + " requires an array")
    return values


def _integer(value, name, lower=0, upper=65535):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(name + " outside integer range")
    return value


def _rows(ctx, parser):
    accepted = []
    for record in ctx.records:
        try:
            accepted.append((record, parser(record.data)))
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError) as exc:
            ctx.issue(record, "invalid_network_record", str(exc)[:1000] or "Invalid record")
    return accepted


def _emit(ctx, kind, summary, rows, artifact_key, extra=None, limitations=()):
    for record, data in rows:
        ctx.finding(kind, summary, [record.record_id], data)
    metrics = {"accepted_records": len(rows), "rejected_records": len(ctx.records) - len(rows)}
    metrics.update(extra or {})
    return ctx.output(metrics=metrics, artifacts={artifact_key: [data for _, data in rows]},
                      limitations=limitations)


def domainint(ctx: AnalysisContext):
    """Normalize IDNA registrations and compare temporal ownership assertions."""
    def parse(data):
        name = _domain(data["domain"])
        created = _date(data["created_at"]) if data.get("created_at") else None
        expiry = _date(data["expires_at"]) if data.get("expires_at") else None
        if created and expiry and expiry <= created:
            raise ValueError("Registration expiry must follow creation")
        return {"domain": name, "registrar": _s(data.get("registrar")) or None,
                "registrant_id": _s(data.get("registrant_id")) or None,
                "created_at": created.isoformat() if created else None,
                "expires_at": expiry.isoformat() if expiry else None,
                "expired_at_snapshot": expiry <= ctx.as_of if expiry else None,
                "days_to_expiry": (expiry - ctx.as_of).total_seconds() / 86400 if expiry else None,
                "registration_active_at_snapshot": not (created and created > ctx.as_of)
                                                    and not (expiry and expiry <= ctx.as_of)}
    rows = _rows(ctx, parse)
    owners = defaultdict(list)
    for record, item in rows:
        if item["registrant_id"] and item["registration_active_at_snapshot"]:
            owners[item["domain"]].append((record, item))
    conflicts = 0
    for name, entries in sorted(owners.items()):
        variants = sorted({item["registrant_id"] for _, item in entries})
        if len(variants) > 1:
            conflicts += 1
            ctx.finding("registration_owner_conflict", "Active supplied registrations assert different registrants.",
                        [record.record_id for record, _ in entries],
                        {"domain": name, "registrant_ids": variants})
    return _emit(ctx, "domain_registration", "Normalized a supplied registration snapshot.",
                 rows, "registrations", {"owner_conflicts": conflicts},
                 ("Registrant and registrar fields are assertions; privacy proxy data does not identify beneficial ownership.",))


def dnsint(ctx: AnalysisContext):
    """Validate typed resource records and detect CNAME exclusivity and cycles."""
    def parse(data):
        owner, kind = _domain(data["name"]), _s(data["type"]).upper()
        ttl = _integer(data.get("ttl", 0), "TTL", 0, 2147483647)
        value = data["value"]
        if kind in {"A", "AAAA"}:
            address = _ip(value)
            if address.version != (4 if kind == "A" else 6):
                raise ValueError("Address family does not match DNS type")
            value = str(address)
        elif kind in {"CNAME", "NS", "PTR", "DNAME"}:
            value = _domain(value)
        elif kind == "MX":
            value = {"preference": _integer(value["preference"], "MX preference"),
                     "exchange": "." if value.get("exchange") == "." else _domain(value["exchange"])}
        elif kind == "TXT":
            value = text(value, "TXT", maximum=16384)
        elif kind == "CAA":
            value = {"flags": _integer(value["flags"], "CAA flags", 0, 255),
                     "tag": text(value["tag"], "CAA tag", maximum=32),
                     "value": text(value["value"], "CAA value", maximum=2048)}
        elif kind == "SOA":
            value = {"mname": _domain(value["mname"]), "rname": _domain(value["rname"]),
                     **{key: _integer(value[key], "SOA " + key, 0, 4294967295)
                        for key in ("serial", "refresh", "retry", "expire", "minimum")}}
        else:
            raise ValueError("Unsupported typed DNS record")
        return {"name": owner, "type": kind, "ttl": ttl, "value": value}
    rows = _rows(ctx, parse)
    names, links = defaultdict(list), defaultdict(set)
    for record, item in rows:
        names[item["name"]].append((record, item))
        if item["type"] == "CNAME":
            links[item["name"]].add(item["value"])
    conflicts, cycles = 0, set()
    for owner, entries in sorted(names.items()):
        aliases = {item["value"] for _, item in entries if item["type"] == "CNAME"}
        kinds = {item["type"] for _, item in entries}
        if len(aliases) > 1 or aliases and kinds - {"CNAME"}:
            conflicts += 1
            ctx.finding("dns_cname_conflict", "Supplied CNAME data conflicts with exclusivity or target consistency.",
                        [record.record_id for record, _ in entries], {"name": owner})
    for start in links:
        stack = [(start, ())]
        visits = 0
        while stack:
            node, path = stack.pop()
            visits += 1
            if visits > 10000:
                ctx.issue(None, "dns_graph_budget", "CNAME traversal budget exhausted.")
                break
            if node in path:
                cycle = path[path.index(node):]
                cycles.add(tuple(sorted(cycle)))
                continue
            stack.extend((target, path + (node,)) for target in sorted(links.get(node, ())))
    for cycle in sorted(cycles):
        refs = [record.record_id for record, item in rows
                if item["name"] in cycle and item["type"] == "CNAME"]
        ctx.finding("dns_cname_cycle", "Supplied aliases contain a directed cycle.", refs,
                    {"members": list(cycle)})
    return _emit(ctx, "dns_resource_record", "Validated a supplied typed resource record.",
                 rows, "records", {"cname_conflicts": conflicts, "cname_cycles": len(cycles)},
                 ("DNS observations can vary by resolver and time; conflicts do not prove poisoning.",))


def ipint(ctx: AnalysisContext):
    """Classify canonical IP literals and test membership in supplied prefixes."""
    def parse(data):
        address = _ip(data["ip"])
        prefixes = [_net(value) for value in _optional(data, "prefixes")]
        ports = sorted({_integer(port, "port", 1, 65535) for port in _optional(data, "ports")})
        return {"ip": str(address), "version": address.version,
                "is_global": address.is_global, "is_private": address.is_private,
                "is_loopback": address.is_loopback, "is_link_local": address.is_link_local,
                "is_multicast": address.is_multicast, "is_unspecified": address.is_unspecified,
                "mapped_ipv4": str(address.ipv4_mapped) if address.version == 6 and address.ipv4_mapped else None,
                "matching_prefixes": sorted(str(prefix) for prefix in prefixes
                                           if prefix.version == address.version and address in prefix),
                "observed_ports": ports}
    return _emit(ctx, "ip_classification", "Classified an IP literal and supplied prefix membership.",
                 _rows(ctx, parse), "addresses",
                 limitations=("Address classification describes the local Python IP database, not reachability, owner or threat reputation.",))


def asnint(ctx: AnalysisContext):
    """Validate autonomous-system numbers and consolidate declared prefix inventories."""
    def parse(data):
        asn = _asn(data["asn"])
        prefixes = sorted({str(_net(value)) for value in _array(data, "prefixes")})
        return {"asn": asn, "as_label": "AS" + str(asn), "prefixes": prefixes,
                "organization_id": _s(data.get("organization_id")) or None,
                "private_use": 64512 <= asn <= 65534 or 4200000000 <= asn <= 4294967294,
                "reserved_zero": asn == 0, "documentation_use": 64496 <= asn <= 64511 or 65536 <= asn <= 65551}
    rows = _rows(ctx, parse)
    groups = defaultdict(list)
    for record, item in rows:
        groups[item["asn"]].append((record, item))
    conflicts = 0
    for asn, items in sorted(groups.items()):
        owners = sorted({item["organization_id"] for _, item in items if item["organization_id"]})
        if len(owners) > 1:
            conflicts += 1
            ctx.finding("asn_owner_conflict", "ASN inventory asserts different organization identifiers.",
                        [record.record_id for record, _ in items], {"asn": asn, "organization_ids": owners})
    return _emit(ctx, "asn_inventory", "Normalized an ASN and declared prefix inventory.", rows, "systems",
                 {"organization_conflicts": conflicts},
                 ("Declared prefixes and organizations are not validated BGP announcements or legal ownership.",))


def bgpint(ctx: AnalysisContext):
    """Evaluate supplied routes against supplied validated ROA payload assertions."""
    rows, prefixes = [], defaultdict(list)
    for record in ctx.records:
        try:
            data = record.data
            route, origin = _net(data["prefix"]), _asn(data["origin_asn"])
            path = [_asn(value) for value in _optional(data, "as_path")]
            if len(path) > 500:
                raise ValueError("AS path too long")
            vrps = []
            for vrp in _array(data, "roas"):
                prefix = _net(vrp["prefix"])
                maximum = _integer(vrp.get("max_length", prefix.prefixlen), "max_length",
                                   prefix.prefixlen, prefix.max_prefixlen)
                vrps.append((prefix, maximum, _asn(vrp["asn"])))
            covering = [(prefix, maximum, asn) for prefix, maximum, asn in vrps
                        if prefix.version == route.version and route.subnet_of(prefix)]
            matching = [(prefix, maximum, asn) for prefix, maximum, asn in covering
                        if asn != 0 and asn == origin and route.prefixlen <= maximum]
            validation = "VALID" if matching else "INVALID" if covering else "NOT_FOUND"
            compressed = [value for index, value in enumerate(path) if not index or value != path[index-1]]
            loop = len(compressed) != len(set(compressed))
            item = {"prefix": str(route), "origin_asn": origin, "as_path": path,
                    "origin_validation": validation, "covering_vrps": len(covering),
                    "matching_vrps": len(matching), "nonconsecutive_as_loop": loop,
                    "path_origin_consistent": path[-1] == origin if path else None,
                    "roa_authenticity_verified": False}
            rows.append((record, item))
            prefixes[str(route)].append((record, item))
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            ctx.issue(record, "invalid_bgp_record", str(exc)[:1000])
    moas = 0
    for prefix, entries in sorted(prefixes.items()):
        origins = sorted({item["origin_asn"] for _, item in entries})
        if len(origins) > 1:
            moas += 1
            ctx.finding("multi_origin_prefix", "The supplied prefix has multiple origin assertions.",
                        [record.record_id for record, _ in entries], {"prefix": prefix, "origins": origins})
    return _emit(ctx, "bgp_origin_validation", "Evaluated the supplied route and ROA payload set.",
                 rows, "routes", {"multi_origin_prefixes": moas},
                 ("VALID is conditional on the supplied VRP set; signatures, freshness and trust anchors were not verified.",
                  "Multiple origins, path loops and invalid origins require review; none alone establishes a hijack."))


def _graph(data):
    nodes = _array(data, "nodes")
    if any(not isinstance(node, str) or not node for node in nodes) or len(set(nodes)) != len(nodes):
        raise ValueError("Nodes require unique nonempty IDs")
    adjacency = {node: set() for node in nodes}
    edges = set()
    for edge in _array(data, "links"):
        if not isinstance(edge, list) or len(edge) != 2 or any(node not in adjacency for node in edge):
            raise ValueError("Links require two declared node IDs")
        a, b = edge
        if a == b:
            raise ValueError("Self links require separate semantics")
        edges.add(tuple(sorted((a, b))))
        adjacency[a].add(b)
        adjacency[b].add(a)
    components, pending = [], set(nodes)
    while pending:
        root = min(pending)
        seen, stack = {root}, [root]
        while stack:
            for target in adjacency[stack.pop()] - seen:
                seen.add(target)
                stack.append(target)
        pending -= seen
        components.append(sorted(seen))
    return adjacency, edges, components


def netint(ctx: AnalysisContext):
    """Find components, articulation candidates and bridges in a declared topology."""
    def parse(data):
        adjacency, edges, components = _graph(data)
        bridges = []
        # At most 500 edges; edge-removal traversal is bounded and avoids recursion.
        for left, right in sorted(edges):
            reached, stack = {left}, [left]
            while stack:
                node = stack.pop()
                for target in adjacency[node] - reached:
                    if {node, target} == {left, right}:
                        continue
                    reached.add(target)
                    stack.append(target)
            if right not in reached:
                bridges.append([left, right])
        return {"nodes": sorted(adjacency), "edges": [list(edge) for edge in sorted(edges)],
                "connected_components": components, "bridges": bridges,
                "degree": {node: len(targets) for node, targets in sorted(adjacency.items())},
                "isolated_nodes": sorted(node for node, targets in adjacency.items() if not targets)}
    return _emit(ctx, "network_topology", "Calculated topology properties from declared links.",
                 _rows(ctx, parse), "topologies",
                 limitations=("Topology results depend on declared links; physical redundancy and live connectivity were not tested.",))


def infraint(ctx: AnalysisContext):
    """Join infrastructure assets by declared provider and shared addresses."""
    def parse(data):
        asset = text(data["asset_id"], "asset_id", maximum=160)
        addresses = sorted({str(_ip(value)) for value in _optional(data, "ips")})
        domains = sorted({_domain(value) for value in _optional(data, "domains")})
        return {"asset_id": asset, "ips": addresses, "domains": domains,
                "provider_id": _s(data.get("provider_id")) or None,
                "service_types": sorted({text(value, "service_type", maximum=80)
                                         for value in _optional(data, "services")})}
    rows = _rows(ctx, parse)
    shared = defaultdict(list)
    for record, item in rows:
        for address in item["ips"]:
            shared[address].append((record, item))
    groups = []
    for address, items in sorted(shared.items()):
        if len({item["asset_id"] for _, item in items}) > 1:
            group = {"ip": address, "asset_ids": sorted({item["asset_id"] for _, item in items}),
                     "ownership_inferred": False}
            groups.append(group)
            ctx.finding("shared_infrastructure_address", "Declared assets share an address.",
                        [record.record_id for record, _ in items], group)
    result = _emit(ctx, "infrastructure_inventory", "Normalized asset/provider/service assertions.",
                   rows, "assets", {"shared_address_groups": len(groups)},
                   ("Shared hosting and provider assertions do not establish common control.",))
    result["artifacts"]["shared_addresses"] = groups
    return result


def _covers(pattern, target):
    if pattern.startswith("*."):
        base = _domain(pattern[2:])
        return target.endswith("." + base) and target.count(".") == base.count(".") + 1
    return _domain(pattern) == target


def certint(ctx: AnalysisContext):
    """Review decoded certificate validity, identity coverage and digest consistency."""
    def parse(data):
        start, end = instant(data["not_before"]), instant(data["not_after"])
        if end <= start:
            raise ValueError("Certificate validity is reversed")
        sans = _array(data, "dns_names")
        normalized = ["*." + _domain(name[2:]) if isinstance(name, str) and name.startswith("*.")
                      else _domain(name) for name in sans]
        target = _domain(data["target"]) if data.get("target") else None
        fingerprint = _s(data.get("sha256")).lower().replace(":", "")
        if fingerprint and not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("Certificate fingerprint must be SHA-256")
        return {"dns_names": sorted(set(normalized)), "target": target,
                "target_name_covered": any(_covers(name, target) for name in normalized) if target else None,
                "not_before": start.isoformat(), "not_after": end.isoformat(),
                "time_valid_at_snapshot": start <= ctx.as_of <= end,
                "days_until_expiry": (end - ctx.as_of).total_seconds() / 86400,
                "sha256": fingerprint or None, "chain_verified": False,
                "issuer": _s(data.get("issuer")) or None}
    return _emit(ctx, "certificate_review", "Reviewed supplied decoded certificate metadata.",
                 _rows(ctx, parse), "certificates",
                 limitations=("Decoded fields and fingerprints are unverified assertions; signature, chain and revocation checks were not performed.",))


def tlsint(ctx: AnalysisContext):
    """Review supplied handshake protocol, cipher and certificate-name assertions."""
    def parse(data):
        version = _s(data["version"]).upper().replace(" ", "")
        aliases = {"TLSV1": "TLS1.0", "TLSV1.0": "TLS1.0", "TLSV1.1": "TLS1.1",
                   "TLSV1.2": "TLS1.2", "TLSV1.3": "TLS1.3", "SSLV3": "SSL3"}
        version = aliases.get(version, version)
        if version not in {"SSL2", "SSL3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}:
            raise ValueError("Unknown TLS version")
        cipher = text(data["cipher"], "cipher", maximum=160).upper()
        weak = sorted({token for token in ("NULL", "EXPORT", "RC4", "3DES", "DES_CBC", "MD5")
                       if token in cipher})
        target = _domain(data["server_name"]) if data.get("server_name") else None
        sans = data.get("certificate_dns_names")
        if sans is not None and not isinstance(sans, list):
            raise ValueError("certificate_dns_names requires an array")
        covered = any(_covers(name, target) for name in sans) if target and sans is not None else None
        return {"version": version, "cipher": cipher,
                "obsolete_protocol": version in {"SSL2", "SSL3", "TLS1.0", "TLS1.1"},
                "weak_cipher_tokens": weak, "server_name": target, "certificate_name_covered": covered,
                "authentication_verified": False}
    return _emit(ctx, "tls_handshake_review", "Reviewed a supplied handshake observation.",
                 _rows(ctx, parse), "handshakes",
                 limitations=("Absence of a known weak token does not establish cipher security; no handshake or trust-chain verification was executed.",))


def cloudint(ctx: AnalysisContext):
    """Evaluate explicit public-access, encryption and IAM wildcard inventory fields."""
    def parse(data):
        asset = text(data["resource_id"], "resource_id", maximum=256)
        checks = {}
        for key in ("public_access", "encrypted", "logging_enabled"):
            if key in data and type(data[key]) is not bool:
                raise ValueError(key + " requires a boolean")
            checks[key] = data.get(key)
        policies = _optional(data, "statements")
        if not isinstance(policies, list):
            raise ValueError("IAM statements require an array")
        wildcards = []
        for index, statement in enumerate(policies):
            if not isinstance(statement, dict) or statement.get("effect") not in {"Allow", "Deny"}:
                raise ValueError("Policy statement needs Allow/Deny effect")
            actions, resources = statement.get("actions", []), statement.get("resources", [])
            if not isinstance(actions, list) or not isinstance(resources, list) or any(
                not isinstance(value, str) for value in actions + resources
            ):
                raise ValueError("Policy actions/resources require text arrays")
            if statement["effect"] == "Allow" and any("*" in value for value in actions + resources):
                wildcards.append({"statement_index": index, "actions": actions, "resources": resources})
        return {"resource_id": asset, "provider": _s(data.get("provider")) or None, **checks,
                "review_flags": [key for key, state in (
                    ("declared_public_access", checks["public_access"] is True),
                    ("declared_unencrypted", checks["encrypted"] is False),
                    ("declared_logging_disabled", checks["logging_enabled"] is False)) if state],
                "allow_wildcards": wildcards, "effective_permissions_computed": False}
    return _emit(ctx, "cloud_configuration_review", "Reviewed explicit cloud-inventory and IAM assertions.",
                 _rows(ctx, parse), "resources",
                 limitations=("IAM conditions, organization policies and deny precedence are not evaluated; wildcard flags are review candidates.",))


def hostint(ctx: AnalysisContext):
    """Compare supplied host services with explicit approved port baselines and support dates."""
    def parse(data):
        host = text(data["host_id"], "host_id", maximum=160)
        ports = sorted({_integer(value, "observed port", 1, 65535) for value in _array(data, "ports")})
        allowed = data.get("approved_ports")
        baseline = sorted({_integer(value, "approved port", 1, 65535) for value in allowed}) if isinstance(allowed, list) else None
        if allowed is not None and baseline is None:
            raise ValueError("approved_ports requires an array")
        support = _date(data["support_ends"]) if data.get("support_ends") else None
        return {"host_id": host, "ports": ports, "approved_ports": baseline,
                "ports_outside_baseline": sorted(set(ports) - set(baseline)) if baseline is not None else None,
                "declared_os": _s(data.get("os")) or None,
                "support_ends": support.isoformat() if support else None,
                "support_ended_at_snapshot": ctx.as_of >= support if support else None}
    return _emit(ctx, "host_baseline_review", "Compared supplied host inventory with its declared baseline.",
                 _rows(ctx, parse), "hosts",
                 limitations=("Ports are supplied observations; no host discovery, vulnerability scan or reachability test ran.",))


def routeint(ctx: AnalysisContext):
    """Select longest-prefix routes, administrative distance and metric with ECMP ties."""
    def parse(data):
        destination = _ip(data["destination"])
        candidates = []
        for route in _array(data, "routes"):
            prefix = _net(route["prefix"])
            hop = _ip(route["next_hop"]) if route.get("next_hop") else None
            if hop and hop.version != prefix.version:
                raise ValueError("Route next-hop family mismatch")
            distance = _integer(route.get("distance", 0), "administrative distance", 0, 255)
            metric = number(route.get("metric", 0), "route metric", minimum=0)
            if prefix.version == destination.version and destination in prefix:
                candidates.append({"prefix": str(prefix), "prefix_length": prefix.prefixlen,
                                   "next_hop": str(hop) if hop else None,
                                   "interface": _s(route.get("interface")) or None,
                                   "distance": distance, "metric": metric})
        rank = lambda row: (-row["prefix_length"], row["distance"], row["metric"])
        candidates.sort(key=lambda row: (rank(row), row["next_hop"] or "", row["interface"] or ""))
        selected = [row for row in candidates if rank(row) == rank(candidates[0])] if candidates else []
        return {"destination": str(destination), "matching_routes": candidates, "selected_routes": selected,
                "selection_state": "ECMP_CANDIDATE" if len(selected) > 1 else "SELECTED" if selected else "NO_ROUTE"}
    return _emit(ctx, "route_selection", "Evaluated a destination against the supplied routing table.",
                 _rows(ctx, parse), "decisions",
                 limitations=("Selection uses the declared table and simple preference rules; recursive next-hop resolution and vendor policy are not simulated.",))


def cdnint(ctx: AnalysisContext):
    """Review captured HTTP cache directives, age and shared-cache exposure candidates."""
    def parse(data):
        url = text(data["url"], "url", maximum=2048)
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("Public capture URL required")
        headers = data["headers"]
        if not isinstance(headers, dict) or any(not isinstance(value, str) for value in headers.values()):
            raise ValueError("Captured headers require string values")
        headers = {key.casefold(): value for key, value in headers.items()}
        directives = {}
        for token in headers.get("cache-control", "").split(","):
            key, _, value = token.strip().partition("=")
            if key:
                directives[key.casefold()] = value.strip('"') or True
        ages = {}
        for key in ("max-age", "s-maxage"):
            if key in directives:
                if not isinstance(directives[key], str) or not re.fullmatch(r"\d+", directives[key]):
                    raise ValueError("Cache duration requires unsigned seconds")
                ages[key] = int(directives[key])
        age = headers.get("age")
        if age is not None and not re.fullmatch(r"\d+", age):
            raise ValueError("Age requires unsigned seconds")
        age = int(age) if age is not None else None
        lifetime = ages.get("s-maxage", ages.get("max-age"))
        flags = []
        if "public" in directives and "set-cookie" in headers:
            flags.append("public_response_with_set_cookie")
        if "no-store" in directives and (age or 0) > 0:
            flags.append("declared_no_store_with_positive_age")
        return {"url": url, "cache_directives": directives, "age_seconds": age,
                "declared_shared_lifetime_seconds": lifetime,
                "fresh_under_supplied_age": age < lifetime if age is not None and lifetime is not None else None,
                "vary_fields": sorted(field.strip().casefold() for field in headers.get("vary", "").split(",") if field.strip()),
                "review_flags": flags, "provider_assertion": _s(data.get("provider_id")) or None,
                "provider_attribution_verified": False}
    return _emit(ctx, "http_cache_review", "Reviewed captured HTTP cache metadata.",
                 _rows(ctx, parse), "cache_observations",
                 limitations=("Age and cache headers are supplied assertions; freshness also depends on HTTP date, request timing and revalidation.",))


def _tags(value):
    tags = {}
    for part in value.split(";"):
        if not part.strip():
            continue
        key, separator, item = part.strip().partition("=")
        if not separator or key.lower() in tags:
            raise ValueError("Malformed or duplicate mail policy tags")
        tags[key.lower()] = item.strip()
    return tags


def mailint(ctx: AnalysisContext):
    """Inspect MX, SPF, DKIM and DMARC inventories without sending mail or resolving DNS."""
    def parse(data):
        domain = _domain(data["domain"])
        mx = []
        for item in _optional(data, "mx"):
            mx.append({"preference": _integer(item["preference"], "MX preference"),
                       "exchange": "." if item["exchange"] == "." else _domain(item["exchange"])})
        if any(item["exchange"] == "." for item in mx) and (len(mx) != 1 or mx[0]["preference"] != 0):
            raise ValueError("Null MX must be the sole preference-zero record")
        spfs = data.get("spf", [])
        if isinstance(spfs, str):
            spfs = [spfs]
        if not isinstance(spfs, list) or any(not isinstance(value, str) for value in spfs):
            raise ValueError("SPF requires text records")
        if any(not value.startswith("v=spf1") for value in spfs):
            raise ValueError("SPF version missing")
        terms = spfs[0].split()[1:] if len(spfs) == 1 else []
        lookup_terms = [value for value in terms if re.split(r"[:=/]", value.lstrip("+-~?"), 1)[0]
                        in {"include", "a", "mx", "ptr", "exists", "redirect"}]
        all_terms = [value for value in terms if value.lstrip("+-~?") == "all"]
        permissive = any(value in {"all", "+all"} for value in all_terms)
        raw_dmarc = data.get("dmarc")
        dmarc = _tags(raw_dmarc) if isinstance(raw_dmarc, str) else None
        if raw_dmarc is not None and dmarc is None:
            raise ValueError("DMARC requires text")
        if dmarc and (dmarc.get("v") != "DMARC1" or dmarc.get("p") not in {"none", "quarantine", "reject"}):
            raise ValueError("DMARC requires version and valid policy")
        if dmarc and "pct" in dmarc:
            if not re.fullmatch(r"\d+", dmarc["pct"]) or not 0 <= int(dmarc["pct"]) <= 100:
                raise ValueError("DMARC pct outside 0-100")
        selectors = []
        for entry in _optional(data, "dkim"):
            selector = text(entry["selector"], "DKIM selector", maximum=128)
            tags = _tags(text(entry["record"], "DKIM record", maximum=16384))
            if tags.get("v", "DKIM1") != "DKIM1" or "p" not in tags:
                raise ValueError("DKIM version/public key missing")
            selectors.append({"selector": selector, "key_type": tags.get("k", "rsa"),
                              "revoked": tags["p"] == "", "key_material_verified": False})
        return {"domain": domain, "mx": sorted(mx, key=lambda item: (item["preference"], item["exchange"])),
                "null_mx": bool(mx and mx[0]["exchange"] == "."),
                "spf_record_count": len(spfs), "spf_multiple_record_error": len(spfs) > 1,
                "spf_direct_lookup_terms": len(lookup_terms),
                "spf_direct_lookup_budget_exceeded": len(lookup_terms) > 10,
                "spf_permissive_all": permissive, "dmarc": dmarc, "dkim_selectors": selectors,
                "spf_evaluation_state": "STATIC_ONLY"}
    return _emit(ctx, "mail_policy_review", "Reviewed supplied mail-routing and authentication policy records.",
                 _rows(ctx, parse), "mail_domains",
                 limitations=("SPF includes/redirects, macros, nested lookup counts and sender authorization require a resolver and sender context; no delivery or signature check ran.",))


def sigint(ctx: AnalysisContext):
    """Measure supplied RF sample statistics, threshold occupancy and sampling feasibility."""
    def parse(data):
        frequency = number(data["center_frequency_hz"], "center frequency", minimum=0)
        bandwidth = number(data["bandwidth_hz"], "bandwidth", minimum=0)
        sample_rate = number(data["sample_rate_hz"], "sample rate", minimum=0.000001)
        samples = [number(value, "sample", minimum=-1e12, maximum=1e12) for value in _array(data, "samples")]
        if not samples:
            raise ValueError("RF sample array is empty")
        threshold = number(data.get("occupancy_threshold", 0), "threshold", minimum=0, maximum=1e12)
        mean = math.fsum(value / len(samples) for value in samples)
        rms = math.sqrt(math.fsum((value / 1e12) ** 2 / len(samples) for value in samples)) * 1e12
        return {"center_frequency_hz": frequency, "bandwidth_hz": bandwidth,
                "sample_rate_hz": sample_rate, "sample_count": len(samples), "mean": mean,
                "rms": rms, "peak_absolute": max(abs(value) for value in samples),
                "threshold_occupancy_fraction": sum(abs(value) > threshold for value in samples) / len(samples),
                "real_sample_nyquist_sufficient": sample_rate >= 2 * bandwidth,
                "declared_sample_duration_seconds": len(samples) / sample_rate,
                "content_decoded": False}
    return _emit(ctx, "supplied_rf_statistics", "Measured statistics on supplied RF samples.",
                 _rows(ctx, parse), "signals",
                 limitations=("No signals were intercepted; sampling adequacy uses a declared real baseband model, not a verified RF front end or emitter identity.",))


def elint(ctx: AnalysisContext):
    """Calculate supplied pulse-train repetition, duty cycle and jitter descriptors."""
    def parse(data):
        frequency = number(data["frequency_hz"], "frequency", minimum=0)
        width = number(data["pulse_width_us"], "pulse width", minimum=0.000001)
        arrivals = [number(value, "pulse arrival", minimum=0, maximum=1e15)
                    for value in _array(data, "pulse_arrivals_us")]
        if len(arrivals) < 2 or any(b <= a for a, b in zip(arrivals, arrivals[1:])):
            raise ValueError("Pulse arrivals require at least two strictly increasing values")
        intervals = [b - a for a, b in zip(arrivals, arrivals[1:])]
        mean = math.fsum(value / len(intervals) for value in intervals)
        if width > min(intervals):
            raise ValueError("Pulse width exceeds an inter-pulse interval")
        variance = math.fsum(((value - mean) / mean) ** 2 / len(intervals) for value in intervals)
        return {"frequency_hz": frequency, "pulse_width_us": width,
                "mean_pri_us": mean, "minimum_pri_us": min(intervals), "maximum_pri_us": max(intervals),
                "prf_hz": 1e6 / mean, "duty_cycle_fraction": width / mean,
                "normalized_pri_jitter": math.sqrt(variance),
                "pulse_count": len(arrivals), "emitter_identified": False}
    return _emit(ctx, "pulse_train_descriptor", "Calculated parameters from supplied pulse observations.",
                 _rows(ctx, parse), "pulse_trains",
                 limitations=("Descriptors do not identify an emitter, platform, intent or location; no RF collection took place.",))


HANDLERS = {
    "SIGINT": sigint, "ELINT": elint, "DOMAININT": domainint, "DNSINT": dnsint,
    "IPINT": ipint, "ASNINT": asnint, "BGPINT": bgpint, "NETINT": netint,
    "INFRAINT": infraint, "CERTINT": certint, "TLSINT": tlsint, "CLOUDINT": cloudint,
    "HOSTINT": hostint, "ROUTEINT": routeint, "CDNINT": cdnint, "MAILINT": mailint,
}
