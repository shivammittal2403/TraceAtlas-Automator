"""Versioned, non-secret contracts for governed intelligence sources."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .sources import SOURCES


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
    max_targets: int = 1
    max_pages: int = 1
    max_response_bytes: int = 5 * 1024 * 1024
    timeout_seconds: int = 30
    unattended_paid_calls: bool = False

    def to_dict(self) -> dict:
        result = asdict(self)
        for key in ("inputs", "allowed_actions", "credential_env"):
            result[key] = list(result[key])
        return result


# These types describe the implemented request validators, not every input a
# provider may advertise. A catalogue row cannot add to this mapping.
SOURCE_INPUTS: dict[str, tuple[str, ...]] = {
    "rdap": ("domain", "ip"), "dns": ("domain",), "wayback": ("domain",),
    "internetdb": ("ip",), "ipwhois": ("ip",), "ipdata": ("ip",),
    "greynoise": ("ip",), "bluesky": ("username",), "github": ("username",),
    "gitlab": ("username",), "hackernews": ("username",), "mastodon": ("username",),
    "stackexchange": ("user_id",), "dockerhub": ("username",), "youtube": ("channel",),
    "discord": ("invite",), "shodan": ("ip",), "censys": ("ip",),
    "virustotal": ("url", "domain", "ip", "hash"), "nvd": ("cve",),
    "npm": ("package",), "crossref": ("doi",), "orcid": ("orcid",),
}

OPTIONAL_CREDENTIALS = {"github", "nvd", "greynoise"}


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
        contract_version=1,
        mode="api" if live else "import",
        inputs=SOURCE_INPUTS.get(source_id, ("approved-export",)),
        allowed_actions=("lookup",) if live else ("ingest",),
        authentication=authentication,
        credential_env=credentials,
        capability_state="implemented" if live else "import-only",
        live_validation="deployment-required" if live else "not-applicable",
    )


def connector_contracts() -> list[dict]:
    return [source_contract(source_id).to_dict() for source_id in sorted(SOURCES)]
