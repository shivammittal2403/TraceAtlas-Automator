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

