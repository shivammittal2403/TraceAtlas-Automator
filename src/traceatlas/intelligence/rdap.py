"""IANA bootstrap routing intersected with explicitly reviewed registry bases.

No redirects, RDAP links, or target-provided hosts become network instructions.
Unknown registry bases fail closed until reviewed and added here.
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import replace
from urllib.parse import quote, urlsplit

from ..policy import validate_target
from .provider import ProviderError

BOOTSTRAP_HOST = "data.iana.org"
# Reviewed against IANA's DNS/IPv4/IPv6 bootstrap registries, 2026-10-03.
RDAP_BASES = frozenset({
    "https://rdap.verisign.com/com/v1/", "https://rdap.verisign.com/net/v1/",
    "https://rdap.publicinterestregistry.org/rdap/",
    "https://pubapi.registry.google/rdap/", "https://rdap.identitydigital.services/rdap/",
    "https://rdap.nic.biz/", "https://rdap.nic.fr/", "https://rdap.nic.gov/rdap/",
    "https://rdap.nixiregistry.in/rdap/", "https://rdap.nominet.uk/uk/",
    "https://rdap.sidn.nl/", "https://rdap.ca.fury.ca/rdap/", "https://rdap.cctld.au/rdap/",
    "https://rdap.afrinic.net/rdap/", "https://rdap.apnic.net/",
    "https://rdap.arin.net/registry/", "https://rdap.db.ripe.net/",
    "https://rdap.lacnic.net/rdap/",
})
RDAP_HOSTS = frozenset(urlsplit(base).hostname for base in RDAP_BASES) | {BOOTSTRAP_HOST}


def bootstrap_url(kind, target):
    normalized = validate_target(kind, target).value
    if kind == "domain":
        filename = "dns"
    elif kind == "ip" and ipaddress.ip_address(normalized).is_global:
        filename = "ipv" + str(ipaddress.ip_address(normalized).version)
    else:
        raise ProviderError("provider_target_rejected")
    return f"https://{BOOTSTRAP_HOST}/rdap/{filename}.json"


def registry_url(kind, target, bootstrap):
    bootstrap_url(kind, target)  # Recheck target even for an injected bootstrap.
    target = validate_target(kind, target).value.lower()
    if (not isinstance(bootstrap, dict) or bootstrap.get("version") != "1.0"
            or not isinstance(bootstrap.get("services"), list) or len(bootstrap["services"]) > 5000):
        raise ProviderError("provider_bootstrap_invalid")
    candidates = []
    for row in bootstrap["services"]:
        if (not isinstance(row, list) or len(row) != 2 or not all(isinstance(v, list) for v in row)
                or any(not isinstance(v, str) or len(v) > 2048 for values in row for v in values)
                or any(len(values) > 2000 for values in row)):
            raise ProviderError("provider_bootstrap_invalid")
        keys, bases = row
        for key in keys:
            if kind == "domain":
                match = target == key.lower() or target.endswith("." + key.lower())
                score = len(key.split(".")) if match and key else 0
            else:
                try:
                    network = ipaddress.ip_network(key, strict=True)
                except ValueError:
                    raise ProviderError("provider_bootstrap_invalid") from None
                address = ipaddress.ip_address(target)
                score = network.prefixlen if address.version == network.version and address in network else 0
            if score:
                candidates.append((score, bases))
    if not candidates:
        raise ProviderError("provider_registry_not_found")
    best = max(score for score, _ in candidates)
    # Never fall back to a less specific allocation, HTTP, or an unreviewed base.
    approved = sorted({base for score, bases in candidates if score == best for base in bases if base in RDAP_BASES})
    if not approved:
        raise ProviderError("provider_registry_not_approved")
    return approved[0] + kind + "/" + quote(target, safe="")


def validate_response(kind, target, data):
    try:
        if kind == "domain":
            matches = (data.get("objectClassName") == "domain"
                       and str(data.get("ldhName", "")).rstrip(".").casefold() == target.casefold())
        else:
            start = ipaddress.ip_address(data["startAddress"])
            end = ipaddress.ip_address(data["endAddress"])
            address = ipaddress.ip_address(target)
            matches = (data.get("objectClassName") == "ip network" and start.version == end.version == address.version
                       and start <= address <= end)
    except (ValueError, KeyError, TypeError):
        matches = False
    if not matches:
        raise ProviderError("provider_target_mismatch")


def lookup(client, kind, target, timeout, *, on_bootstrap=None):
    deadline = time.monotonic() + min(30, max(0, timeout))
    url = bootstrap_url(kind, target)
    bootstrap = client.get("rdap_bootstrap", url, {"Accept": "application/json"}, timeout)
    if on_bootstrap:
        on_bootstrap(url, bootstrap)
    response = None
    try:
        endpoint = registry_url(kind, target, bootstrap.data)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderError("provider_deadline_exceeded")
        response = client.get("rdap", endpoint, {"Accept": "application/rdap+json", "User-Agent": "TraceAtlas-Automator/1.10"}, remaining)
        validate_response(kind, target, response.data)
    except ProviderError as exc:
        if response is not None:
            exc.attempts = response.attempts
        exc.attempts += bootstrap.attempts
        raise
    return endpoint, replace(response, attempts=bootstrap.attempts + response.attempts)
