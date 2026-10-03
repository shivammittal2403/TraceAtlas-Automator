"""Versioned, non-secret contracts for governed intelligence sources."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .sources import SOURCES
from .rdap import RDAP_HOSTS

SOURCE_HOSTS = {
    'cloudflare_dns': 'cloudflare-dns.com', 'crtsh': 'crt.sh', 'ripestat': 'stat.ripe.net',
    'gleif': 'api.gleif.org', 'companieshouse': 'api.company-information.service.gov.uk',
    'sec': 'data.sec.gov', 'opencorporates': 'api.opencorporates.com',
    'rdap': 'data.iana.org', 'dns': 'dns.google', 'wayback': 'web.archive.org', 'urlscan': 'urlscan.io',
    "epss": "api.first.org", "osv": "api.osv.dev",
    'internetdb': 'internetdb.shodan.io', 'ipwhois': 'ipwho.is', 'ipdata': 'api.ipdata.co',
    'greynoise': 'api.greynoise.io', 'bluesky': 'public.api.bsky.app', 'github': 'api.github.com',
    'gitlab': 'gitlab.com', 'hackernews': 'hacker-news.firebaseio.com', 'mastodon': 'mastodon.social',
    'stackexchange': 'api.stackexchange.com', 'dockerhub': 'hub.docker.com', 'youtube': 'www.googleapis.com',
    'discord': 'discord.com', 'shodan': 'api.shodan.io', 'censys': 'search.censys.io',
    'virustotal': 'www.virustotal.com', 'nvd': 'services.nvd.nist.gov', 'npm': 'registry.npmjs.org',
    'crossref': 'api.crossref.org', 'orcid': 'pub.orcid.org',
}
# This is the supported local integration contract, not a claim about every
# address family a provider may support outside this connector.
IPV4_ONLY = frozenset({'internetdb', 'greynoise'})


@dataclass(frozen=True, slots=True)
class ConnectorContract:
    source_id: str
    contract_version: int
    mode: str
    inputs: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    authentication: str
    credential_env: tuple[str, ...]
    capability_state: str
    live_validation: str
    allowed_hosts: tuple[str, ...] = ()
    supported_ip_versions: tuple[int, ...] = ()
    max_targets: int = 1
    max_pages: int = 1
    max_response_bytes: int = 5 * 1024 * 1024
    timeout_seconds: int = 30
    unattended_paid_calls: bool = False

    def to_dict(self) -> dict:
        result = asdict(self)
        for key in ("inputs", "allowed_actions", "credential_env", "allowed_hosts", "supported_ip_versions"):
            result[key] = list(result[key])
        return result


# These types describe the implemented request validators, not every input a
# provider may advertise. A catalogue row cannot add to this mapping.
SOURCE_INPUTS: dict[str, tuple[str, ...]] = {
    "cloudflare_dns": ("domain",), "crtsh": ("domain",), "ripestat": ("ip",),
    "gleif": ("company",), "companieshouse": ("company",), "sec": ("company",), "opencorporates": ("company",),
    "rdap": ("domain", "ip"), "dns": ("domain",), "wayback": ("domain",), "urlscan": ("domain", "ip"),
    "epss": ("cve",), "osv": ("vulnerability",),
    "internetdb": ("ip",), "ipwhois": ("ip",), "ipdata": ("ip",),
    "greynoise": ("ip",), "bluesky": ("username",), "github": ("username", "company"),
    "gitlab": ("username",), "hackernews": ("username",), "mastodon": ("username",),
    "stackexchange": ("user_id",), "dockerhub": ("username",), "youtube": ("channel",),
    "discord": ("invite",), "shodan": ("ip",), "censys": ("ip",),
    "virustotal": ("url", "domain", "ip", "hash"), "nvd": ("cve",),
    "npm": ("package",), "crossref": ("doi",), "orcid": ("orcid",),
}

OPTIONAL_CREDENTIALS = {"github", "nvd", "greynoise", "urlscan"}


def source_contract(source_id: str) -> ConnectorContract:
    spec = SOURCES[source_id]
    live = bool(spec.live_connector and source_id in SOURCE_INPUTS)
    credentials = tuple(spec.credential_env)
    authentication = (
        "optional-secret-reference" if source_id in OPTIONAL_CREDENTIALS
        else "secret-reference" if credentials else "none"
    )
    return ConnectorContract(
        source_id=source_id,
        contract_version=2 if source_id == "rdap" else 1,
        mode="api" if live else "import",
        inputs=SOURCE_INPUTS.get(source_id, ("approved-export",)),
        allowed_actions=("lookup",) if live else ("ingest",),
        authentication=authentication,
        credential_env=credentials,
        capability_state="implemented" if live else "import-only",
        live_validation="deployment-required" if live else "not-applicable",
        allowed_hosts=tuple(sorted(RDAP_HOSTS)) if source_id == "rdap" else (SOURCE_HOSTS[source_id],) if live else (),
        supported_ip_versions=(4,) if source_id in IPV4_ONLY else (4, 6) if 'ip' in SOURCE_INPUTS.get(source_id, ()) else (),
        max_pages=2 if source_id == "rdap" else 1,
    )


def connector_contracts() -> list[dict]:
    return [source_contract(source_id).to_dict() for source_id in sorted(SOURCES)]
