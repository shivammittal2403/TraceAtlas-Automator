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
    elif source == 'cisa_kev':
        expected = target.strip().upper()
        rows = data.get('vulnerabilities', []) if isinstance(data, dict) else []
        matches = [row for row in rows if isinstance(row, dict) and row.get('cveID') == expected]
        if len(matches) != 1:
            raise ProviderError('provider_record_not_found' if not matches else 'provider_target_mismatch')
        record = matches[0]
        try:
            added = datetime.strptime(record['dateAdded'], '%Y-%m-%d').replace(tzinfo=timezone.utc)
            datetime.strptime(record['dueDate'], '%Y-%m-%d')
        except (KeyError, TypeError, ValueError):
            raise ProviderError('provider_schema_mismatch') from None
        at = added.isoformat()
        add('vulnerability_id', expected, at)
        add('cisa_kev_listed', 'true', at)
        add('cisa_kev_added_date', record['dateAdded'], at)
        add('cisa_kev_due_date', record['dueDate'], at)
        add('cisa_kev_required_action', record['requiredAction'][:1000], at)
        add('cisa_kev_vulnerability_name', record['vulnerabilityName'][:500], at)
        add('affected_product', record['vendorProject'][:300] + ' / ' + record['product'][:300], at)
    elif source == 'nvd':
        rows = data['vulnerabilities']
        if data['totalResults'] < 1 or not rows:
            raise ProviderError('provider_record_not_found')
        matches = [row['cve'] for row in rows if isinstance(row, dict) and isinstance(row.get('cve'), dict)
                   and row['cve'].get('id') == target]
        if len(matches) != 1:
            raise ProviderError('provider_target_mismatch')
        record = matches[0]
        at = _provider_time(record.get('lastModified'), stamp)
        add('vulnerability_id', target, at)
        kev_added = record.get('cisaExploitAdd')
        if kev_added is not None:
            if not isinstance(kev_added, str):
                raise ProviderError('provider_schema_mismatch')
            try:
                datetime.strptime(kev_added, '%Y-%m-%d')
            except ValueError:
                raise ProviderError('provider_schema_mismatch') from None
            kev_at = _provider_time(kev_added, at)
            add('cisa_kev_listed', 'true', kev_at)
            add('cisa_kev_added_date', kev_added, kev_at)
            due_date = record.get('cisaActionDue')
            if due_date is not None:
                if not isinstance(due_date, str):
                    raise ProviderError('provider_schema_mismatch')
                try:
                    datetime.strptime(due_date, '%Y-%m-%d')
                except ValueError:
                    raise ProviderError('provider_schema_mismatch') from None
                add('cisa_kev_due_date', due_date, at)
            for field, predicate in (('cisaRequiredAction', 'cisa_kev_required_action'),
                                     ('cisaVulnerabilityName', 'cisa_kev_vulnerability_name')):
                value = record.get(field)
                if value is not None:
                    if not isinstance(value, str) or len(value) > 500:
                        raise ProviderError('provider_schema_mismatch')
                    add(predicate, value, at)
        metrics = record.get('metrics', {})
        if not isinstance(metrics, dict):
            raise ProviderError('provider_schema_mismatch')
        for metric_name in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            values = metrics.get(metric_name, [])
            if values:
                if not isinstance(values, list) or not isinstance(values[0], dict) or not isinstance(values[0].get('cvssData'), dict):
                    raise ProviderError('provider_schema_mismatch')
                cvss = values[0]['cvssData']
                score = cvss.get('baseScore')
                if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= float(score) <= 10:
                    raise ProviderError('provider_schema_mismatch')
                add('vulnerability_score', str(score), at)
                severity = cvss.get('baseSeverity') or values[0].get('baseSeverity')
                if isinstance(severity, str):
                    add('vulnerability_severity', severity.upper(), at)
                break
    elif source == 'cveorg':
        metadata = data.get('cveMetadata', {})
        containers = data.get('containers', {})
        cna = containers.get('cna', {}) if isinstance(containers, dict) else {}
        if not isinstance(metadata, dict) or metadata.get('cveId') != target:
            raise ProviderError('provider_target_mismatch')
        if not isinstance(cna, dict):
            raise ProviderError('provider_schema_mismatch')
        at = _provider_time(metadata.get('datePublished') or metadata.get('dateUpdated'), stamp)
        add('vulnerability_id', target, at)
        title = cna.get('title')
        if not isinstance(title, str):
            descriptions = cna.get('descriptions', [])
            if not isinstance(descriptions, list):
                raise ProviderError('provider_schema_mismatch')
            description = next((row for row in descriptions[:25]
                                if isinstance(row, dict) and row.get('lang') in {'en', 'en-US'}
                                and isinstance(row.get('value'), str)), None)
            title = description.get('value') if description else None
        if isinstance(title, str) and title.strip():
            add('vulnerability_name', title.strip()[:500], at)
        affected = cna.get('affected', [])
        if not isinstance(affected, list):
            raise ProviderError('provider_schema_mismatch')
        for item in affected[:25]:
            if not isinstance(item, dict):
                raise ProviderError('provider_schema_mismatch')
            vendor, product = item.get('vendor'), item.get('product')
            if isinstance(product, str) and product.strip():
                vendor_label = vendor.strip()[:200] if isinstance(vendor, str) else ''
                product_label = product.strip()[:200]
                add('affected_product', (vendor_label + ':' if vendor_label else '') + product_label, at)
    elif source == 'epss':
        rows = data['data']
        if not rows:
            raise ProviderError('provider_record_not_found')
        row = rows[0]
        if row['cve'] != target:
            raise ProviderError('provider_target_mismatch')
        at = _provider_time(row.get('date'), stamp)
        for predicate, key in (('exploitation_probability', 'epss'), ('exploitation_percentile', 'percentile')):
            value = row.get(key)
            try:
                valid = value is not None and not isinstance(value, bool) and 0 <= float(value) <= 1
            except (TypeError, ValueError):
                valid = False
            if not valid:
                raise ProviderError('provider_schema_mismatch')
            add(predicate, str(value), at)
    elif source == 'osv':
        aliases = data.get('aliases', [])
        if data['id'] != target and target not in aliases:
            raise ProviderError('provider_target_mismatch')
        at = _provider_time(data.get('modified'), stamp)
        add('vulnerability_id', data['id'], at)
        if not isinstance(aliases, list):
            raise ProviderError('provider_schema_mismatch')
        for alias in aliases[:20]:
            if isinstance(alias, str) and alias != target:
                add('vulnerability_alias', alias, at)
        for affected in data['affected'][:100]:
            package = affected.get('package') if isinstance(affected, dict) else None
            if not isinstance(package, dict) or not isinstance(package.get('ecosystem'), str) or not isinstance(package.get('name'), str):
                raise ProviderError('provider_schema_mismatch')
            add('affected_package', package['ecosystem'] + ':' + package['name'], at)
    elif source == 'npm':
        if data['name'].casefold() != target.casefold():
            raise ProviderError('provider_target_mismatch')
        add('package_version', data['version'])
        license_value = data.get('license')
        if isinstance(license_value, str):
            add('package_license', license_value)
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


def _provider_time(value, fallback):
    if not isinstance(value, str):
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        try:
            parsed = datetime.strptime(value, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        except ValueError:
            raise ProviderError('provider_schema_mismatch') from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


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
