"""Governed module catalogue for the supplied IntelOwl feature inventory.

The catalogue is deliberately separate from execution.  Display names from a
spreadsheet or report are not assumed to be valid plugin identifiers.  Before
an analyzer can run, its exact name and supported observable types must be
discovered from the operator's IntelOwl instance.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from ..policy import PolicyError


ANALYZER_TITLES = tuple(line.strip() for line in """
AbuseIPDB
Abusix
AdGuard
AIL Typosquatting
Androguard
APIVoid
APKiD
Artifacts
Auth0
BBOT
BGP Ranking
BinaryEdge
BitcoinAbuse
Blint Scan
BoxJS Scan
CAPA Info
CAPE Sandbox
Censys
CheckDMARC
CheckPhish
CIRCL PDNS
CIRCL PSSL
ClamAV
Classic DNS Resolver
CleanBrowsing Malicious Detector
Cloudflare DNS Resolver
Cloudflare Malicious Detector
CriminalIP
CriminalIP Scan
CrowdSec
crt.sh
CRXcavator
Cuckoo Scan
CVE Exploitability
CyberChef
CyCat
Cymru
Debloat
DetectItEasy
DNS4EU Resolver
DNS4EU Malicious Detector
DNSDB
DNStwist
Doc Info
DocGuard
DocGuard Get
Download File From URI
DroidLysis
DShield
ELF Info
EmailRep
Expand URL
Feodo Tracker
File Info
FileScan
FileScan Search
FireHOL IPList
FLOSS
Google DNS Resolver
Google WebRisk
Google Safe Browsing
GoReSym
GreedyBear
GreyNoise Intel
GuardDog File
GuardDog Generic
Hashlookup
HaveIBeenPwned
HFinger
HIBP Breaches
HIBP Passwords
HoneyDB
HudsonRock
Hunter How
Hunter.io
Hunting Abuse
InQuest
IntelX
Intezer Get
Intezer Scan
IOCExtract
IOCFinder
IP2Location
IP2Whois
IPAPI
IPInfo
IPQS
IPQS File
IPQS URL
IPQuery
JA4 DB
JoeSandbox
JoeSandbox File
KnockAnalyzer
Koodous
LeakIX
LNK Info
MachO Info
Malpedia Scan
MalProb
MaxMind
MalwareBazaar Get
MalwareBazaar Google
MISP
MMDB Server
Mnemonic PDNS
MobSF
MobSF Service
Mullvad DNS
MWDB Get
MWDB Scan
NERD
Netlas
Nuclei
NVD CVE
OneNote
OnionScan
Onyphe
OpenCTI
ORKL Search
OTX
PDF Info
PE Info
PEFrame
Perm Hash
Phishing Army
Phishing Extractor
Phishing Form Compiler
PhishStats
PhishTank
PhoneInfoga Scan
PHunter
PolySwarm
PolySwarm Obs
Pulsedive
Qiling
Quad9 DNS Resolver
Quad9 Malicious Detector
Quark Engine
RDAP
Robtex
RTF Info
SecurityTrails
Shodan
Signature Info
Slack
Spamhaus DROP
Spamhaus WQS
Speakeasy Emulation
Spyse
SS API Net
StalkPhish
Stratosphere
Strings Info
Sublime
Suricata
Talos
ThreatFox
Tor Project
Tranco
Triage
Triage Get
Triage Scan
URLhaus
UrlScan
VirusTotal
VirusTotal File
VirusTotal URL
WhoisXML
XForce
YARA
YARA Rules
ZoomEye
Abuse Submitter
Email Sender
MISP Connector
OpenCTI Connector
Slack Connector
Email Connector
Webhook Connector
Elasticsearch Connector
TheHive Connector
Mattermost Connector
Microsoft Teams Connector
Discord Connector
Generic Webhook
Custom Analyzer Framework
""".strip().splitlines())


CONNECTOR_TITLES = frozenset({
    "Abuse Submitter", "Email Sender", "MISP Connector", "OpenCTI Connector",
    "Slack Connector", "Email Connector", "Webhook Connector",
    "Elasticsearch Connector", "TheHive Connector", "Mattermost Connector",
    "Microsoft Teams Connector", "Discord Connector", "Generic Webhook",
})

# The TraceAtlas bridge intentionally has no file-upload endpoint.  These remain
# visible for planning, but cannot be selected for observable execution.
FILE_ONLY_TITLES = frozenset({
    "Androguard", "APKiD", "Artifacts", "Blint Scan", "BoxJS Scan", "CAPA Info",
    "CAPE Sandbox", "ClamAV", "CRXcavator", "Cuckoo Scan", "CyberChef", "Debloat",
    "DetectItEasy", "Doc Info", "DocGuard", "DocGuard Get", "Download File From URI",
    "DroidLysis", "ELF Info", "File Info", "FileScan", "FLOSS", "GoReSym",
    "GuardDog File", "IPQS File", "JoeSandbox File", "LNK Info", "MachO Info",
    "MobSF", "MobSF Service", "OneNote", "PDF Info", "PE Info", "PEFrame",
    "Phishing Extractor", "Phishing Form Compiler", "Qiling", "Quark Engine",
    "RTF Info", "Signature Info", "Speakeasy Emulation", "Strings Info", "Suricata",
    "Triage Scan", "VirusTotal File", "YARA", "YARA Rules",
})


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _match_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


@dataclass(frozen=True, slots=True)
class IntelligenceModule:
    id: str
    title: str
    family: str
    kind: str
    execution: str
    target_types: tuple[str, ...]
    restriction: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["target_types"] = list(self.target_types)
        return value


def _build_catalog() -> dict[str, IntelligenceModule]:
    modules: dict[str, IntelligenceModule] = {}
    for title in ANALYZER_TITLES:
        module_id = _slug(title)
        if title in CONNECTOR_TITLES:
            kind = "connector"
            execution = "catalogued"
            targets: tuple[str, ...] = ()
            restriction = "Outbound delivery is not enabled by the TraceAtlas core."
        elif title == "Custom Analyzer Framework":
            kind = "framework"
            execution = "catalogued"
            targets = ()
            restriction = "Runtime code/plugin installation is never accepted through TraceAtlas."
        elif title in FILE_ONLY_TITLES:
            kind = "analyzer"
            execution = "file-route-blocked"
            targets = ()
            restriction = "File upload and malware execution are excluded from this service bridge."
        else:
            kind = "analyzer"
            execution = "runtime-discovered"
            targets = ("domain", "ip", "url", "hash")
            restriction = "Exact remote name and target support must be verified from IntelOwl first."
        if module_id in modules:
            raise RuntimeError(f"Duplicate module identifier: {module_id}")
        modules[module_id] = IntelligenceModule(
            module_id, title, "intelowl", kind, execution, targets, restriction,
        )
    return modules


MODULE_CATALOG = _build_catalog()


def catalog_rows(*, query: str = "", kind: str = "") -> list[dict[str, Any]]:
    query_key = query.strip().lower()
    if kind and kind not in {"analyzer", "connector", "framework"}:
        raise PolicyError("Module kind must be analyzer, connector or framework")
    return [
        module.to_dict() for module in MODULE_CATALOG.values()
        if (not query_key or query_key in module.title.lower() or query_key in module.id)
        and (not kind or module.kind == kind)
    ]


def normalize_remote_configs(payload: Any) -> list[dict[str, Any]]:
    """Normalize supported IntelOwl analyzer-config response shapes."""
    if isinstance(payload, dict):
        for key in ("results", "items", "analyzers"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            mapped = []
            for name, config in payload.items():
                if isinstance(config, dict):
                    mapped.append({"name": name, **config})
            payload = mapped
    if not isinstance(payload, list) or len(payload) > 1000:
        raise ValueError("IntelOwl analyzer configuration has an unsupported shape or size")
    rows = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        supported = item.get("observable_supported", [])
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", name):
            continue
        if not isinstance(supported, list):
            supported = []
        rows.append({
            "name": name,
            "disabled": item.get("disabled") is True,
            "observable_supported": sorted({
                str(value).lower() for value in supported
                if str(value).lower() in {"domain", "ip", "url", "hash", "generic"}
            }),
        })
    return rows


def _remote_matches(module: IntelligenceModule,
                    remote: list[dict[str, Any]]) -> list[dict[str, Any]]:
    local_key = _match_key(module.title)
    exact = [row for row in remote if _match_key(row["name"]) == local_key]
    if exact:
        return exact
    return [row for row in remote if (
        _match_key(row["name"]).startswith(local_key)
        or local_key.startswith(_match_key(row["name"]))
    )]


def resolve_remote_modules(module_ids: Iterable[str], payload: Any,
                           target_type: str) -> list[str]:
    """Resolve local catalogue IDs to exact enabled remote analyzer names."""
    if target_type not in {"domain", "ip", "url", "hash"}:
        raise PolicyError("IntelOwl module target type is invalid")
    requested = list(module_ids)
    if not 1 <= len(requested) <= 25 or len(set(requested)) != len(requested):
        raise PolicyError("Select 1-25 unique IntelOwl modules")
    remote = normalize_remote_configs(payload)
    selected: list[str] = []
    for module_id in requested:
        module = MODULE_CATALOG.get(module_id)
        if module is None:
            raise PolicyError(f"Unknown IntelOwl module: {module_id}")
        if module.execution != "runtime-discovered":
            raise PolicyError(f"IntelOwl module is not enabled for observable execution: {module_id}")
        # Conservative fallback handles suffixes used by upstream (for example,
        # OTXQuery) only when the match is unambiguous.
        matches = _remote_matches(module, remote)
        if len(matches) != 1:
            raise PolicyError(
                f"Module {module_id} did not resolve to one exact IntelOwl analyzer; "
                "inspect `intel module-doctor`"
            )
        match = matches[0]
        if match["disabled"]:
            raise PolicyError(f"IntelOwl analyzer is disabled: {match['name']}")
        supported = set(match["observable_supported"])
        if target_type not in supported and "generic" not in supported:
            raise PolicyError(
                f"IntelOwl analyzer {match['name']} does not advertise {target_type} support"
            )
        selected.append(match["name"])
    return selected


def reconcile_catalog(payload: Any) -> dict[str, Any]:
    """Report remote coverage without claiming that an analyzer has executed."""
    remote = normalize_remote_configs(payload)
    resolved = []
    unresolved = []
    ambiguous = []
    for module in MODULE_CATALOG.values():
        if module.execution != "runtime-discovered":
            continue
        matches = _remote_matches(module, remote)
        if len(matches) == 1:
            resolved.append({"id": module.id, **matches[0]})
        elif len(matches) > 1:
            ambiguous.append({"id": module.id, "candidates": [row["name"] for row in matches]})
        else:
            unresolved.append(module.id)
    return {
        "catalogued": len(MODULE_CATALOG),
        "analyzers": sum(item.kind == "analyzer" for item in MODULE_CATALOG.values()),
        "connectors": sum(item.kind == "connector" for item in MODULE_CATALOG.values()),
        "frameworks": sum(item.kind == "framework" for item in MODULE_CATALOG.values()),
        "remote_analyzers": len(remote),
        "resolved": resolved,
        "ambiguous": ambiguous,
        "unresolved": unresolved,
        "execution_verified": False,
        "note": "Discovery verifies configuration only; a successful case run is separate evidence.",
    }
