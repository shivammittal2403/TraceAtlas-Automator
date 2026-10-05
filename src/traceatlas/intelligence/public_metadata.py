"""Exact public metadata contracts; linked files and personal contacts are excluded."""
import re
from urllib.parse import quote

from ..policy import PolicyError
from .provider import ProviderError


def package_identity(value):
    return re.sub(r'[-_.]+', '-', value).lower()


def python_project(target):
    if not isinstance(target, str) or not target.startswith('pypi:'):
        raise PolicyError('Python package seeds require an explicit pypi: ecosystem prefix')
    project = target[5:]
    if not re.fullmatch(r'[A-Z0-9](?:[A-Z0-9._-]{0,126}[A-Z0-9])?', project, re.I):
        raise PolicyError('PyPI requires one exact unscoped Python project name')
    return project


def build_request(source, kind, target):
    if source == 'pypi':
        if kind != 'package':
            raise PolicyError('PyPI requires a package seed')
        return 'https://pypi.org/pypi/' + quote(package_identity(python_project(target)), safe='') + '/json'
    if source == 'datacite':
        if kind != 'doi' or len(target) > 253 or not re.fullmatch(r'10\.\d{4,9}/[-._;()/:A-Z0-9]+', target, re.I):
            raise PolicyError('DataCite requires one exact DOI')
        return 'https://api.datacite.org/dois/' + quote(target, safe='')
    raise PolicyError('Unsupported public metadata provider')


def validate_shape(source, data):
    valid = False
    if source == 'pypi' and isinstance(data, dict):
        info, files = data.get('info'), data.get('urls')
        valid = (isinstance(info, dict) and isinstance(info.get('name'), str)
                 and isinstance(info.get('version'), str) and isinstance(files, list) and len(files) <= 1000
                 and all(isinstance(f, dict) and isinstance(f.get('filename'), str)
                         and isinstance(f.get('digests'), dict)
                         and isinstance(f['digests'].get('sha256'), str)
                         and re.fullmatch(r'[a-fA-F0-9]{64}', f['digests']['sha256']) for f in files))
    elif source == 'datacite' and isinstance(data, dict):
        record = data.get('data')
        attributes = record.get('attributes') if isinstance(record, dict) else None
        titles = attributes.get('titles') if isinstance(attributes, dict) else None
        valid = (isinstance(record, dict) and record.get('type') == 'dois'
                 and isinstance(record.get('id'), str) and isinstance(attributes, dict)
                 and isinstance(attributes.get('doi'), str) and isinstance(titles, list)
                 and 1 <= len(titles) <= 100 and all(isinstance(t, dict) and isinstance(t.get('title'), str) for t in titles))
    if not valid:
        raise ProviderError('provider_schema_mismatch')


def normalize(source, kind, target, data):
    build_request(source, kind, target)
    validate_shape(source, data)
    if source == 'pypi':
        info = data['info']
        if package_identity(info['name']) != package_identity(python_project(target)):
            raise ProviderError('provider_target_mismatch')
        return [{'entity_type': 'PACKAGE', 'ecosystem': 'PyPI', 'name': info['name'],
            'version': info['version'], 'license_assertion': info.get('license_expression') or info.get('license'),
            'requires_python': info.get('requires_python'),
            'files': [{'filename': f['filename'], 'sha256': f['digests']['sha256'],
                       'yanked': f.get('yanked'), 'uploaded_at': f.get('upload_time_iso_8601')}
                      for f in data['urls']],
            'source_assertion': True, 'publisher_claims_verified': False}]
    record, attributes = data['data'], data['data']['attributes']
    if record['id'].casefold() != target.casefold() or attributes['doi'].casefold() != target.casefold():
        raise ProviderError('provider_target_mismatch')
    return [{'entity_type': 'PUBLICATION', 'doi': attributes['doi'],
             'titles': [{'title': t['title'], 'language': t.get('lang')} for t in attributes['titles']],
             'publication_year': attributes.get('publicationYear'),
             'types': attributes.get('types'), 'registered': attributes.get('registered'),
             'updated': attributes.get('updated'), 'source_assertion': True,
             'publication_claims_verified': False}]
