from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class SourceSpec:
    name: str
    title: str
    category: str
    acquisition: str
    event_type: str
    description: str
    live_connector: bool = False
    credential_env: tuple[str, ...] = ()
    personal_data: bool = False
    public_record: bool = False
    limitation: str = "An observation is not proof of identity, ownership or wrongdoing."

    def to_dict(self) -> dict:
        data = asdict(self)
        data["credential_env"] = list(self.credential_env)
        return data


def _source(name: str, title: str, category: str, acquisition: str,
            event_type: str, description: str, **kwargs) -> SourceSpec:
    return SourceSpec(name, title, category, acquisition, event_type, description, **kwargs)


SOURCES: dict[str, SourceSpec] = {
    "pypi": _source("pypi", "Python Package Index", "package-intelligence", "public-registry-api",
        "PACKAGE_RECORD", "Exact Python project metadata; no package downloads or execution.",
        live_connector=True, public_record=True,
        limitation="Publisher-supplied metadata is not package safety, ownership, or license clearance."),
    "datacite": _source("datacite", "DataCite DOI Metadata", "scholarly-intelligence", "public-metadata-api",
        "PUBLICATION_RECORD", "Exact registered DOI metadata, excluding author contact information.",
        live_connector=True, public_record=True,
        limitation="Metadata attribution does not prove publication truth or rights to the referenced content."),
    "cloudflare_dns": _source("cloudflare_dns", "Cloudflare DNS", "internet-registration", "public-doh",
        "DNS_RECORD", "Public DNS through the Cloudflare JSON resolver.", live_connector=True),
    "crtsh": _source("crtsh", "crt.sh", "certificate-intelligence", "public-index-api",
        "CERTIFICATE_RECORD", "Historical certificate log metadata for an exact domain; no host probing.", live_connector=True),
    "ripestat": _source("ripestat", "RIPEstat", "internet-intelligence", "public-api",
        "IP_CONTEXT", "Announced network prefix and ASNs for an exact public IP.", live_connector=True),
    "gleif": _source("gleif", "GLEIF LEI", "business-intelligence", "public-registry-api",
        "BUSINESS_RECORD", "Exact legal-entity reference record by LEI.", live_connector=True, public_record=True),
    "companieshouse": _source("companieshouse", "UK Companies House", "business-intelligence", "public-registry-api",
        "BUSINESS_RECORD", "Exact UK company profile by registration number.", live_connector=True, public_record=True,
        credential_env=("COMPANIES_HOUSE_API_KEY",)),
    "sec": _source("sec", "SEC EDGAR", "business-intelligence", "public-government-api",
        "BUSINESS_RECORD", "Public filer identity and recent filing metadata by exact CIK.", live_connector=True,
        public_record=True, credential_env=("SEC_USER_AGENT",)),
    "opencorporates": _source("opencorporates", "OpenCorporates", "business-intelligence", "licensed-api",
        "BUSINESS_RECORD", "Exact registry record by jurisdiction and company number; upstream attribution preserved.",
        live_connector=True, public_record=True, credential_env=("OPENCORPORATES_API_TOKEN",)),
    "epss": _source("epss", "FIRST EPSS", "vulnerability-intelligence", "public-api",
        "VULNERABILITY_RECORD", "Exact CVE exploitation probability metadata.", live_connector=True,
        public_record=True, limitation="EPSS is a dated probability estimate, not observed exploitation of this asset."),
    "osv": _source("osv", "OSV", "vulnerability-intelligence", "public-api",
        "VULNERABILITY_RECORD", "Exact vulnerability record, aliases and affected package metadata.",
        live_connector=True, public_record=True, limitation="An advisory does not prove an installed package is affected."),
    "rdap": _source(
        "rdap", "RDAP", "internet-registration", "public-rdap",
        "REGISTRATION_RECORD", "Authoritative registration metadata for a public domain or IP.",
        live_connector=True, public_record=True,
    ),
    "dns": _source(
        "dns", "DNS over HTTPS", "internet-registration", "public-doh",
        "DNS_RECORD", "Public DNS answers through a fixed DNS-over-HTTPS resolver.",
        live_connector=True,
    ),
    "wayback": _source(
        "wayback", "Internet Archive CDX", "web-archive", "public-index-api",
        "ARCHIVED_URL", "Public web-archive index metadata; archived pages are not fetched.",
        live_connector=True,
    ),
    "urlscan": _source(
        "urlscan", "urlscan.io Search", "web-archive", "public-index-api",
        "ARCHIVED_URL", "Read-only search of existing scans for an authorized domain or public IP.",
        live_connector=True, credential_env=("URLSCAN_API_KEY",),
        limitation="Historical scan metadata only; no scan submissions or automatic URL fetches. Anonymous quotas are limited.",
    ),
    "internetdb": _source(
        "internetdb", "Shodan InternetDB", "internet-intelligence", "public-api",
        "INTERNET_EXPOSURE", "Keyless passive service metadata for an organisation-owned public IP.",
        live_connector=True,
    ),
    "ipwhois": _source(
        "ipwhois", "IPWHOIS.io", "internet-intelligence", "public-api",
        "IP_CONTEXT", "Approximate network and geography context for an organisation-owned public IP.",
        live_connector=True,
        limitation="IP geolocation is approximate network context, never proof of a person's location.",
    ),
    "ipdata": _source(
        "ipdata", "ipdata", "internet-intelligence", "api",
        "IP_CONTEXT", "Network, ASN and approximate geography context for an organisation-owned public IP.",
        live_connector=True, credential_env=("IPDATA_API_KEY",),
        limitation="Provider fields vary by subscription; IP geography is approximate network context.",
    ),
    "greynoise": _source(
        "greynoise", "GreyNoise Community", "threat-intelligence", "public-api",
        "THREAT_INTELLIGENCE", "Rate-limited community context for an organisation-owned public IPv4 address.",
        live_connector=True, credential_env=("GREYNOISE_API_KEY",),
        limitation="A GreyNoise classification is a provider observation, not proof of current malicious activity.",
    ),
    "linkedin": _source(
        "linkedin", "LinkedIn", "social-professional", "official-export",
        "PROFESSIONAL_PROFILE", "Consented profile or owned-organisation API/export records.",
        personal_data=True,
    ),
    "instagram": _source(
        "instagram", "Instagram", "social-media", "official-export",
        "SOCIAL_PROFILE", "Consented public-profile or official API/export observations.",
        personal_data=True,
    ),
    "facebook": _source(
        "facebook", "Facebook", "social-media", "official-export",
        "SOCIAL_PROFILE", "Consented public-page or official API/export observations.",
        personal_data=True,
    ),
    "tiktok": _source(
        "tiktok", "TikTok", "social-media", "official-export",
        "SOCIAL_PROFILE", "Consented public-profile or official API/export observations.",
        personal_data=True,
    ),
    "snapchat": _source(
        "snapchat", "Snapchat", "social-media", "official-export",
        "SOCIAL_PROFILE", "Consented public-profile or official API/export observations.",
        personal_data=True,
    ),
    "bluesky": _source(
        "bluesky", "Bluesky", "social-media", "public-appview-api-or-export",
        "SOCIAL_PROFILE", "Public profile metadata through the Bluesky AppView API or an export.",
        live_connector=True, personal_data=True,
    ),
    "mastodon": _source(
        "mastodon", "Mastodon", "social-media", "public-instance-api-or-export",
        "SOCIAL_PROFILE", "Exact public account metadata through a fixed Mastodon instance API or an export.",
        live_connector=True, credential_env=("MASTODON_ACCESS_TOKEN",), personal_data=True,
    ),
    "reddit": _source(
        "reddit", "Reddit", "community-platform", "official-export",
        "SOCIAL_PROFILE", "Consented public-account or moderator-approved community export.",
        personal_data=True,
    ),
    "x": _source(
        "x", "X", "social-media", "official-export",
        "SOCIAL_PROFILE", "Consented public-profile or official API/export observations.",
        personal_data=True,
    ),
    "telegram": _source(
        "telegram", "Telegram", "community-platform", "official-export",
        "COMMUNITY_METADATA", "Public-channel or owned-community export; no private messages.",
        personal_data=True,
    ),
    "rss": _source(
        "rss", "RSS / Atom", "public-web", "approved-export",
        "PUBLIC_CONTENT", "Approved RSS/Atom export normalized as public content records.",
    ),
    "youtube": _source(
        "youtube", "YouTube", "video-platform", "api-or-export",
        "PUBLIC_MEDIA_PROFILE", "Public channel metadata through YouTube Data API or an export.",
        live_connector=True, credential_env=("YOUTUBE_API_KEY",), personal_data=True,
    ),
    "github": _source(
        "github", "GitHub", "code-platform", "public-api-or-export",
        "CODE_PROFILE", "Public user or organisation metadata through GitHub API or an export.",
        live_connector=True, credential_env=("GITHUB_TOKEN",), personal_data=True,
    ),
    "gitlab": _source(
        "gitlab", "GitLab", "code-platform", "public-api-or-export",
        "CODE_PROFILE", "Exact public username metadata through GitLab's official Users API or an export.",
        live_connector=True, personal_data=True,
    ),
    "hackernews": _source(
        "hackernews", "Hacker News", "community-platform", "public-api-or-export",
        "SOCIAL_PROFILE", "Exact public user metadata through the official Hacker News API or an export.",
        live_connector=True, personal_data=True,
    ),
    "stackexchange": _source(
        "stackexchange", "Stack Exchange", "community-platform", "public-api-or-export",
        "SOCIAL_PROFILE", "One exact public Stack Overflow user record through Stack Exchange API v2.3.",
        live_connector=True, personal_data=True,
    ),
    "dockerhub": _source(
        "dockerhub", "Docker Hub", "code-platform", "public-api-or-export",
        "CODE_PROFILE", "A bounded public repository listing for one exact Docker Hub namespace.",
        live_connector=True, personal_data=True,
    ),
    "discord": _source(
        "discord", "Discord", "community-platform", "public-invite-api-or-export",
        "COMMUNITY_METADATA", "Public invite/community metadata; no private messages or member scraping.",
        live_connector=True, personal_data=True,
    ),
    "shodan": _source(
        "shodan", "Shodan", "internet-intelligence", "api-or-export",
        "INTERNET_EXPOSURE", "Observed service metadata for an organisation-owned public IP.",
        live_connector=True, credential_env=("SHODAN_API_KEY",),
    ),
    "censys": _source(
        "censys", "Censys", "internet-intelligence", "api-or-export",
        "INTERNET_EXPOSURE", "Observed service metadata for an organisation-owned public IP.",
        live_connector=True, credential_env=("CENSYS_API_ID", "CENSYS_API_SECRET"),
    ),
    "virustotal": _source(
        "virustotal", "VirusTotal", "threat-intelligence", "api-or-export",
        "THREAT_INTELLIGENCE", "Reputation metadata for an owned indicator; samples are never downloaded.",
        live_connector=True, credential_env=("VIRUSTOTAL_API_KEY",),
    ),
    "cveorg": _source(
        "cveorg", "CVE Program", "vulnerability-intelligence", "official-public-api",
        "VULNERABILITY_RECORD", "One exact public CVE Record from the CVE Program API; no exploit code is retrieved.",
        live_connector=True, public_record=True,
        limitation="A published CNA record is a source statement, not proof that a product is installed or affected."
    ),
    "cisa_kev": _source(
        "cisa_kev", "CISA Known Exploited Vulnerabilities Catalog", "vulnerability-intelligence",
        "official-government-feed", "VULNERABILITY_RECORD",
        "One exact CVE row matched from CISA’s published KEV catalog; the fixed-host feed is filtered before case evidence is stored.",
        live_connector=True, public_record=True,
        limitation="Catalog inclusion is a CISA listing observation; it does not prove an investigated asset runs or is exploitable by this CVE."
    ),
    "nvd": _source(
        "nvd", "NIST National Vulnerability Database", "vulnerability-intelligence",
        "public-government-api", "VULNERABILITY_RECORD",
        "One exact public CVE record through the NVD CVE API; no exploit code is retrieved.",
        live_connector=True, public_record=True,
    ),
    "npm": _source(
        "npm", "npm Registry", "package-intelligence", "public-registry-api",
        "PACKAGE_RECORD", "The current public metadata record for one exact npm package.",
        live_connector=True, public_record=True,
    ),
    "crossref": _source(
        "crossref", "Crossref", "scholarly-intelligence", "public-metadata-api",
        "SCHOLARLY_RECORD", "One exact public DOI metadata record through the Crossref REST API.",
        live_connector=True, public_record=True,
    ),
    "orcid": _source(
        "orcid", "ORCID", "social-professional", "public-api-or-export",
        "PROFESSIONAL_PROFILE", "Public person metadata for one exact ORCID iD using a read-public token.",
        live_connector=True, credential_env=("ORCID_ACCESS_TOKEN",), personal_data=True,
    ),
    "malwarebazaar": _source(
        "malwarebazaar", "MalwareBazaar", "threat-intelligence", "approved-export",
        "THREAT_INTELLIGENCE", "Approved hash/feed export; malware binaries are never downloaded.",
    ),
    "business_registry": _source(
        "business_registry", "Business registry", "business-intelligence", "authoritative-export",
        "BUSINESS_RECORD", "Authoritative company-registry, filing or ownership export.",
        public_record=True,
    ),
    "employee_directory": _source(
        "employee_directory", "Employee directory", "organisation-intelligence", "owned-directory-export",
        "PROFESSIONAL_RECORD", "Owned directory or consented professional records; private contacts are redacted.",
        personal_data=True,
    ),
    "sanctions": _source(
        "sanctions", "Sanctions records", "public-record", "authoritative-export",
        "SANCTIONS_RECORD", "Authoritative public sanctions-list export for documented due diligence.",
        public_record=True,
    ),
    "court_records": _source(
        "court_records", "Court records", "public-record", "authoritative-export",
        "COURT_RECORD", "Lawfully accessible official court-record export; allegations are not convictions.",
        public_record=True,
        limitation="A filing or name match is not proof of identity, guilt or conviction.",
    ),
}
