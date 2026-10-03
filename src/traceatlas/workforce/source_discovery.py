"""A review queue, never a network destination or executable plugin loader."""
from __future__ import annotations

import json
import re
from importlib.resources import files

ALIASES = {
    'wayback cdx': 'wayback', 'internet archive': 'wayback', 'internet archive media': 'wayback',
    'common crawl historical indexes': 'common-crawl', 'common crawl': 'common-crawl',
    'lei reference data': 'gleif', 'gleif': 'gleif',
    'openownership register': 'openownership', 'openownership': 'openownership',
    'eu financial sanctions': 'eu-sanctions', 'eu sanctions': 'eu-sanctions',
    'github api': 'github', 'github code search': 'github', 'github events': 'github',
    'github social/developer signals': 'github', 'github advisory database': 'github-advisories',
    'github security advisories': 'github-advisories', 'github advisories': 'github-advisories',
    'first epss': 'epss', 'exploit prediction scoring system': 'epss', 'epss': 'epss',
    'world bank apis': 'world-bank-open-data', 'world bank open data': 'world-bank-open-data',
    'eu ted procurement': 'eu-ted', 'eu ted': 'eu-ted',
    'google public dns': 'dns', 'cloudflare dns': 'cloudflare_dns',
    'icann rdap': 'rdap', 'verisign rdap': 'rdap', 'iana': 'rdap',
    'censys certificates': 'censys', 'shodan dns': 'shodan',
    'virustotal domain intelligence': 'virustotal', 'urlscan.io': 'urlscan',
    'companies house uk': 'companieshouse', 'sec edgar': 'sec',
    'brave search': 'brave', 'certificate transparency history': 'certificate-transparency-logs',
    'ipinfo': 'ipinfo', 'noaa weather': 'noaa', 'youtube data api': 'youtube',
    'nvd': 'nvd', 'cve.org': 'cve-org', 'cisa kev': 'cisa-kev',
    'mapillary imagery': 'mapillary', 'sentinel imagery': 'sentinel-data',
    'copernicus imagery': 'copernicus-data-space', 'nasa imagery': 'nasa-earthdata',
    'usgs imagery': 'usgs', 'gitlab api': 'gitlab', 'gitlab public activity': 'gitlab',
}
GENERIC = ('capabilities where', 'providers', 'sources', 'datasets', 'registries', 'public records', 'public services',
           'publications', 'local analysis', 'engines', 'public blockchain data', 'perceptual hashing', 'git history',
           'package-version history', 'institutional repositories', 'public issue trackers', 'public community archives',
           'public mailing-list archives', 'stix/taxii feeds', 'vendor psirts')


def canonical_source_name(name):
    text = re.sub(r'\s+where\b.*$', '', name.casefold()).strip()
    return ALIASES.get(text, re.sub(r'[^a-z0-9]+', '-', text).strip('-'))


def candidate_catalog():
    from .source_registry import SourceRegistry
    data = json.loads(files('traceatlas.workforce.data').joinpath('source_candidates.json').read_text())
    existing = {r.source_id: r for r in SourceRegistry().list()}
    grouped = {}
    for candidate in data['candidates']:
        source_id = canonical_source_name(candidate['name'])
        row = grouped.setdefault(source_id, {'source_id': source_id, 'name': candidate['name'], 'candidate_numbers': [],
            'families': [], 'state': 'DISCOVERED', 'execution_enabled': False,
            'review': {k: candidate[k] for k in ('api_availability', 'authentication', 'pricing', 'rate_limits', 'terms', 'license', 'maintenance')}})
        row['candidate_numbers'].append(candidate['candidate_number'])
        if candidate['family'] not in row['families']: row['families'].append(candidate['family'])
        row['requires_specific_provider'] = any(term in candidate['name'].casefold() for term in GENERIC)
        if source_id in existing:
            manifest = existing[source_id]
            row['existing_source_id'] = source_id
            row['implementation_status'] = manifest.implementation_status
            row['documentation_url'] = manifest.documentation_url
    rows = sorted(grouped.values(), key=lambda r: r['candidate_numbers'][0])
    return {'schema': data['schema'], 'input_sha256': data['input_sha256'], 'candidate_entries': len(data['candidates']),
        'deduplicated_review_rows': len(rows), 'generic_categories': sum(r['requires_specific_provider'] for r in rows),
        'additional_implemented_connectors': 0, 'production_qualified': 0,
        'duplicates': [r for r in rows if len(r['candidate_numbers']) > 1], 'sources': rows,
        'limitation': 'Discovery records are not verified APIs, implemented adapters or production qualifications.'}
