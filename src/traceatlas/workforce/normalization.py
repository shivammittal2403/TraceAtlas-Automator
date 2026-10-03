"""Deterministic provider normalization shared by the source SDK and offline replay."""
from __future__ import annotations
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlsplit
from ..intelligence.provider import ProviderError, _validate_shape
from ..intelligence.rdap import validate_response as validate_rdap_response
from .documents import StructuredFact
from .live_sources import SEARCH_SOURCES

def live_facts(source, seed, data, stamp):
    try:
        return _live_facts(source, seed, data, stamp)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError):
        raise ProviderError('provider_schema_mismatch') from None


def _live_facts(source, seed, data, stamp):
    _validate_shape(source, data)
    facts = []
    def add(predicate, value, at=stamp):
        if isinstance(value, (str, int)) and str(value).strip():
            facts.append(StructuredFact(seed, predicate, str(value), at, at))
    kind, target = seed.split(":", 1)
    if source in {"dns", "cloudflare_dns"}:
        questions = data.get("Question", [])
        if not any(isinstance(q, dict) and str(q.get("name", "")).rstrip(".").casefold() == target for q in questions):
            raise ProviderError("provider_target_mismatch")
        if data["Status"] == 0:
            for row in data.get("Answer", [])[:100]:
                if isinstance(row, dict) and row.get("type") in {1, 28} and str(row.get("name", "")).rstrip(".").casefold() == target:
                    add("resolves_to", row.get("data"))
    elif source == "rdap":
        validate_rdap_response(kind, target, data)
        add("registry_handle", data.get("handle"))
        add("registered_name", data.get("ldhName") if kind == "domain" else data.get("name"))
        if kind == "ip":
            add("registered_country", data.get("country"))
        for status in data.get("status", [])[:20]:
            add("registration_status", status)
    elif source == "crtsh":
        for row in data[:100]:
            names = row["name_value"].lower().splitlines()
            if target not in names and ('*.' + target) not in names:
                raise ProviderError("provider_target_mismatch")
            stamp_value = row.get("entry_timestamp")
            if not isinstance(stamp_value, str):
                raise ProviderError("provider_schema_mismatch")
            # crt.sh entry_timestamp is specified as UTC, commonly without a suffix.
            at = datetime.fromisoformat(stamp_value.replace('Z', '+00:00'))
            if at.tzinfo is None:
                at = at.replace(tzinfo=timezone.utc)
            add("certificate_log_id", row["id"], at.astimezone(timezone.utc).isoformat())
    elif source == "ripestat":
        info = data['data']
        prefix = info.get('prefix')
        if prefix is not None:
            network = ipaddress.ip_network(prefix)
            if ipaddress.ip_address(target) not in network:
                raise ProviderError('provider_target_mismatch')
            add('announced_prefix', prefix)
            for asn in info['asns'][:20]:
                if isinstance(asn, bool) or not str(asn).isdigit():
                    raise ProviderError('provider_schema_mismatch')
                add('network_asn', asn)
    elif source in {'gleif', 'companieshouse', 'sec', 'opencorporates', 'github'}:
        from ..intelligence.registry_requests import company_identifier
        parts = company_identifier(source, target)
        if source == 'gleif':
            record = data['data']; attributes = record['attributes']; entity = attributes['entity']
            if record.get('id') != parts[0] or attributes.get('lei') != parts[0]:
                raise ProviderError('provider_target_mismatch')
            add('registry_handle', parts[0]); add('registered_name', entity.get('legalName', {}).get('name'))
            add('registered_country', entity.get('legalAddress', {}).get('country'))
            add('registration_status', entity.get('status'))
        elif source == 'companieshouse':
            if data['company_number'] != parts[0]:
                raise ProviderError('provider_target_mismatch')
            add('registry_handle', data['company_number']); add('registered_name', data['company_name'])
            add('registration_status', data['company_status'])
        elif source == 'sec':
            if int(data['cik']) != int(parts[0]):
                raise ProviderError('provider_target_mismatch')
            add('registry_handle', data['cik']); add('registered_name', data['name'])
            recent = data['filings'].get('recent', {})
            accessions, dates = recent.get('accessionNumber', []), recent.get('filingDate', [])
            if not isinstance(accessions, list) or not isinstance(dates, list) or len(accessions) != len(dates):
                raise ProviderError('provider_schema_mismatch')
            for accession, date in list(zip(accessions, dates))[:20]:
                at = datetime.strptime(date, '%Y-%m-%d').replace(tzinfo=timezone.utc).isoformat()
                add('filing_accession', accession, at)
        elif source == 'github':
            if data['login'].lower() != parts[0].lower() or data.get('type') != 'Organization':
                raise ProviderError('provider_target_mismatch')
            add('public_label', data.get('name')); add('repository_count', data.get('public_repos'))
            url = _public_result_url(data.get('html_url'))
            if url:
                add('organization_profile', url)
        else:
            company = data['results']['company']
            if company['jurisdiction_code'] != parts[0] or company['company_number'] != parts[1]:
                raise ProviderError('provider_target_mismatch')
            retrieved = company.get('retrieved_at')
            if not isinstance(retrieved, str):
                raise ProviderError('provider_schema_mismatch')
            at = datetime.fromisoformat(retrieved.replace('Z', '+00:00'))
            if at.tzinfo is None:
                raise ProviderError('provider_schema_mismatch')
            at = at.astimezone(timezone.utc).isoformat()
            add('registry_handle', company['company_number'], at)
            add('registered_name', company['name'], at); add('registration_status', company.get('current_status'), at)
    elif source == 'shodan':
        if ipaddress.ip_address(data['ip_str']) != ipaddress.ip_address(target):
            raise ProviderError('provider_target_mismatch')
        for port in data.get('ports', [])[:100]:
            add('observed_port', port)
    elif source == 'virustotal':
        record = data['data']
        actual = record.get('id')
        matches = actual == target if kind == 'domain' else ipaddress.ip_address(actual) == ipaddress.ip_address(target)
        if not matches:
            raise ProviderError('provider_target_mismatch')
        attributes = record.get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        if not isinstance(stats, dict):
            raise ProviderError('provider_schema_mismatch')
        count = stats.get('malicious')
        if type(count) is int and count >= 0:
            add('provider_malicious_detections', count)
    elif source == "internetdb":
        if ipaddress.ip_address(data["ip"]) != ipaddress.ip_address(target):
            raise ProviderError("provider_target_mismatch")
        for port in data.get("ports", [])[:100]:
            add("observed_port", port)
    elif source in {"ipwhois", "ipdata", "greynoise"}:
        if ipaddress.ip_address(data["ip"]) != ipaddress.ip_address(target):
            raise ProviderError("provider_target_mismatch")
        if source == "greynoise":
            add("provider_classification", data.get("classification"))
            add("provider_last_seen", data.get("last_seen"))
        else:
            add("approximate_country", data.get("country_code"))
            network = data.get("connection", {}) if source == "ipwhois" else data.get("asn", {})
            if isinstance(network, dict):
                add("network_asn", network.get("asn"))
                add("network_isp", network.get("isp") if source == "ipwhois" else network.get("name"))
    elif source in SEARCH_SOURCES:
        query = data["query"]["original"] if source == "brave" else data["query"]
        if query != '"' + target + '"':
            raise ProviderError("provider_target_mismatch")
        rows = data.get("web", {}).get("results", []) if source == "brave" else data["results"]
        for row in rows[:10]:
            if not isinstance(row, dict):
                raise ProviderError("provider_schema_mismatch")
            url = _public_result_url(row.get("url"))
            if url:
                add("search_result_url", url)
    elif source == "urlscan":
        for row in data["results"]:
            if not isinstance(row, dict):
                raise ProviderError("provider_schema_mismatch")
            page, task = row.get("page", {}), row.get("task", {})
            if not isinstance(page, dict) or not isinstance(task, dict):
                raise ProviderError("provider_schema_mismatch")
            # Missing optional fields yield no assertions; different targets fail closed.
            if kind == "domain" and page.get("domain") is not None:
                if str(page["domain"]).rstrip(".").lower() != target:
                    raise ProviderError("provider_target_mismatch")
            elif kind == "ip" and page.get("ip") is not None:
                if ipaddress.ip_address(page["ip"]) != ipaddress.ip_address(target):
                    raise ProviderError("provider_target_mismatch")
            else:
                continue
            at = task.get("time")
            if not isinstance(at, str):
                continue
            parsed_time = datetime.fromisoformat(at.replace("Z", "+00:00"))
            if parsed_time.tzinfo is None:
                raise ProviderError("provider_schema_mismatch")
            at = parsed_time.astimezone(timezone.utc).isoformat()
            url = _public_result_url(page.get("url"))
            if url and (kind == "ip" or (urlsplit(url).hostname or "").lower() == target):
                add("indexed_url", url, at)
            if page.get("ip"):
                add("scan_observed_ip", str(ipaddress.ip_address(page["ip"])), at)
    elif source == "wayback":
        if not data:
            return ()
        header = data[0]
        if "original" not in header or "timestamp" not in header:
            raise ProviderError("provider_schema_mismatch")
        for row in data[1:101]:
            if not isinstance(row, list) or len(row) != len(header):
                raise ProviderError("provider_schema_mismatch")
            record = dict(zip(header, row))
            host = (urlsplit(record["original"]).hostname or "").lower()
            if host != target and not host.endswith("." + target):
                raise ProviderError("provider_target_mismatch")
            try:
                at = datetime.strptime(record["timestamp"], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).isoformat()
                add("archived_url", record["original"], at)
            except (ValueError, TypeError):
                raise ProviderError("provider_schema_mismatch") from None
    return tuple(facts)


def _public_result_url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 500 or any(ord(c) < 33 for c in value):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        if parsed.hostname.lower() in {"localhost", "localhost.localdomain"}:
            return None
        try:
            if not ipaddress.ip_address(parsed.hostname).is_global:
                return None
        except ValueError:
            pass
    except ValueError:
        return None
    return value
