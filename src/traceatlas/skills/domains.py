"""Canonical intelligence-domain taxonomy for TraceAtlas.

This module is descriptive/routing metadata. A domain being listed here does not
mean TraceAtlas has a production-qualified collector for it. Execution remains
governed by skill/source registries and policy.
"""
from __future__ import annotations

from dataclasses import dataclass

FAMILIES = (
    "web_socmint",
    "geo_media",
    "infra_cyber",
    "cti_malware",
    "fin_scam",
    "corporate_public_records",
    "document_forensics",
    "identity_entity",
    "graph_timeline",
    "evidence_verification",
    "hypothesis_analysis",
    "reporting_decision_support",
)


@dataclass(frozen=True, slots=True)
class IntelligenceDomain:
    domain_id: str
    title: str
    family: str
    aliases: tuple[str, ...] = ()
    execution_class: str = "analysis"
    sensitive: bool = False

    def __post_init__(self) -> None:
        if self.family not in FAMILIES:
            raise ValueError(f"unknown intelligence family: {self.family}")


_ROWS = [
("osint","Open Source Intelligence","web_socmint",("open-source-intelligence",)),
("socmint","Social Media Intelligence","web_socmint",("social-media-intelligence",)),
("webint","Web Intelligence","web_socmint",()),
("geoint","Geospatial Intelligence","geo_media",()),
("imint","Imagery Intelligence","geo_media",()),
("vidint","Video Intelligence","geo_media",()),
("audint","Audio Intelligence","geo_media",("audio-intelligence",)),
("sigint","Signals Intelligence","infra_cyber",(), "restricted", True),
("comint","Communications Intelligence","infra_cyber",(), "restricted", True),
("elint","Electronic Intelligence","infra_cyber",(), "restricted", True),
("cybint","Cyber Intelligence","infra_cyber",()),
("cti","Cyber Threat Intelligence","cti_malware",()),
("techint","Technical Intelligence","infra_cyber",()),
("netint","Network Intelligence","infra_cyber",()),
("infraint","Internet/Infrastructure Intelligence","infra_cyber",()),
("dnsint","DNS Intelligence","infra_cyber",("dns-intelligence",)),
("domainint","Domain Intelligence","infra_cyber",("domain-intelligence",)),
("ipint","IP Intelligence","infra_cyber",("ip-intelligence",)),
("malint","Malware Intelligence","cti_malware",()),
("vulnint","Vulnerability Intelligence","cti_malware",()),
("exploit-int","Exploit Intelligence","cti_malware",()),
("threat-actor-int","Threat Actor Intelligence","cti_malware",()),
("ioc-int","IOC Intelligence","cti_malware",()),
("ttp-int","TTP Intelligence","cti_malware",()),
("darkint","Dark-Web Intelligence","web_socmint",("dark-web-intelligence",), "controlled", True),
("breach-int","Breach Intelligence","cti_malware",()),
("credint","Credential Exposure Intelligence","cti_malware",(), "controlled", True),
("humint","Human Intelligence","identity_entity",(), "controlled", True),
("finint","Financial Intelligence","fin_scam",()),
("tradeint","Trade Intelligence","corporate_public_records",()),
("corpint","Corporate/Business Intelligence","corporate_public_records",("business-intelligence",)),
("orgint","Organisational Intelligence","corporate_public_records",()),
("supply-chain-int","Supply-Chain Intelligence","corporate_public_records",()),
("scamint","Scam/Fraud Intelligence","fin_scam",("fraud-intelligence",)),
("payment-int","Payment Intelligence","fin_scam",()),
("cryptoint","Blockchain/Crypto Intelligence","fin_scam",("blockchain-intelligence",)),
("sanctions-int","Sanctions Intelligence","corporate_public_records",()),
("procurement-int","Procurement Intelligence","corporate_public_records",()),
("legalint","Legal Intelligence","corporate_public_records",()),
("regint","Regulatory Intelligence","corporate_public_records",()),
("polint","Political Intelligence","corporate_public_records",()),
("govint","Government/Public-Record Intelligence","corporate_public_records",()),
("milint","Military Intelligence","geo_media",(), "controlled", True),
("stratint","Strategic Intelligence","reporting_decision_support",()),
("tactint","Tactical Intelligence","reporting_decision_support",()),
("opint","Operational Intelligence","reporting_decision_support",()),
("crimint","Criminal Intelligence","fin_scam",(), "controlled", True),
("counterint","Counterintelligence","hypothesis_analysis",(), "controlled", True),
("ctint","Counter-Terrorism Intelligence","hypothesis_analysis",("terrorism-intelligence",), "controlled", True),
("marint","Maritime Intelligence","geo_media",()),
("aviint","Aviation Intelligence","geo_media",("airint",)),
("spaceint","Space Intelligence","geo_media",()),
("satint","Satellite Intelligence","geo_media",()),
("rfint","Radio-Frequency Intelligence","infra_cyber",(), "restricted", True),
("ais-int","AIS Intelligence","geo_media",()),
("adsb-int","ADS-B Intelligence","geo_media",()),
("metint","Measurement Intelligence","geo_media",()),
("masint","Measurement and Signature Intelligence","geo_media",(), "controlled", True),
("radint","Radar Intelligence","geo_media",(), "restricted", True),
("acoustint","Acoustic Intelligence","geo_media",()),
("seisint","Seismic Intelligence","geo_media",()),
("nucint","Nuclear-Signature Intelligence","geo_media",(), "restricted", True),
("envint","Environmental Intelligence","geo_media",()),
("weather-int","Weather Intelligence","geo_media",()),
("mapint","Mapping/Cartographic Intelligence","geo_media",()),
("locint","Location Intelligence","geo_media",()),
("mobint","Mobility/Movement Intelligence","geo_media",()),
("transport-int","Transport Intelligence","geo_media",()),
("logint","Logistics Intelligence","corporate_public_records",()),
("mediaint","Media Intelligence","geo_media",()),
("newsint","News Intelligence","web_socmint",()),
("disinfo-int","Disinformation Intelligence","web_socmint",()),
("narrative-int","Narrative Intelligence","web_socmint",()),
("influence-int","Influence/Meme Intelligence","web_socmint",()),
("langint","Language Intelligence","document_forensics",()),
("lingint","Linguistic Intelligence","document_forensics",()),
("docint","Document Intelligence","document_forensics",()),
("document-forensics-int","PDF/Document Forensics Intelligence","document_forensics",()),
("email-int","Email Intelligence","document_forensics",()),
("phoneint","Phone Intelligence","identity_entity",(), "controlled", True),
("username-int","Username Intelligence","identity_entity",()),
("identity-int","Identity Intelligence","identity_entity",()),
("person-int","Person Intelligence","identity_entity",(), "controlled", True),
("relationship-int","Relationship Intelligence","graph_timeline",()),
("graph-int","Graph Intelligence","graph_timeline",()),
("timeline-int","Timeline Intelligence","graph_timeline",()),
("event-int","Event Intelligence","graph_timeline",()),
("behavioural-int","Behavioural Intelligence","hypothesis_analysis",(), "controlled", True),
("pattern-int","Pattern Intelligence","hypothesis_analysis",()),
("anomaly-int","Anomaly Intelligence","hypothesis_analysis",()),
("forensic-int","Forensic Intelligence","document_forensics",()),
("dfir-int","DFIR Intelligence","document_forensics",()),
("host-int","Host Intelligence","infra_cyber",()),
("cloudint","Cloud Intelligence","infra_cyber",()),
("container-int","Container Intelligence","infra_cyber",()),
("codeint","Source-Code Intelligence","infra_cyber",()),
("repoint","Repository Intelligence","infra_cyber",()),
("devint","Developer/Ecosystem Intelligence","infra_cyber",()),
("package-int","Package Intelligence","infra_cyber",()),
("sbom-int","SBOM Intelligence","infra_cyber",()),
("aiint","AI Ecosystem Intelligence","infra_cyber",()),
("llmint","LLM Intelligence","infra_cyber",()),
("modelint","Model Intelligence","infra_cyber",()),
("dataint","Dataset Intelligence","document_forensics",()),
("research-int","Research Intelligence","corporate_public_records",()),
("patint","Patent Intelligence","corporate_public_records",()),
("academic-int","Academic Intelligence","corporate_public_records",()),
("healthint","Public-Health Intelligence","corporate_public_records",(), "controlled", True),
("bioint","Biological Intelligence","corporate_public_records",(), "controlled", True),
("econint","Economic Intelligence","corporate_public_records",()),
("marketint","Market Intelligence","corporate_public_records",()),
("competitive-int","Competitive Intelligence","corporate_public_records",()),
("risk-int","Risk Intelligence","reporting_decision_support",()),
("reputation-int","Reputation Intelligence","web_socmint",()),
("brand-int","Brand Intelligence","web_socmint",()),
("fraudint","Fraud Intelligence","fin_scam",()),
("scam-network-int","Scam Network Intelligence","fin_scam",()),
("asset-int","Asset Intelligence","infra_cyber",()),
("facility-int","Facility Intelligence","geo_media",()),
("energyint","Energy Intelligence","corporate_public_records",()),
("ics-ot-int","ICS/OT Intelligence","infra_cyber",()),
("scada-int","SCADA Intelligence","infra_cyber",()),
("iot-int","IoT Intelligence","infra_cyber",()),
("automotive-int","Automotive Intelligence","infra_cyber",()),
("maritime-cyber-int","Maritime Cyber Intelligence","infra_cyber",()),
("aviation-cyber-int","Aviation Cyber Intelligence","infra_cyber",()),
("source-int","Source Intelligence","evidence_verification",()),
("provenance-int","Provenance Intelligence","evidence_verification",()),
("evidence-int","Evidence Intelligence","evidence_verification",()),
("hypothesis-int","Hypothesis Intelligence","hypothesis_analysis",()),
("contradiction-int","Contradiction Intelligence","hypothesis_analysis",()),
("corroboration-int","Corroboration Intelligence","evidence_verification",()),
("deception-int","Deception Intelligence","hypothesis_analysis",()),
("attribution-int","Attribution Intelligence","hypothesis_analysis",(), "controlled", True),
("knowledge-int","Knowledge Intelligence","hypothesis_analysis",()),
("kag","Knowledge-Augmented Intelligence","hypothesis_analysis",("knowledge-augmented-generation",)),
("rag","RAG-based Intelligence","hypothesis_analysis",("retrieval-augmented-generation",)),
("multimodal-int","Multimodal Intelligence","geo_media",()),
("fusion-int","Fusion Intelligence","hypothesis_analysis",()),
("decision-int","Decision Intelligence","reporting_decision_support",()),
]

DOMAINS = tuple(IntelligenceDomain(*row) for row in _ROWS)
BY_ID = {row.domain_id: row for row in DOMAINS}
ALIASES = {
    alias.casefold(): row.domain_id
    for row in DOMAINS
    for alias in (row.domain_id, row.title, *row.aliases)
}


def resolve_domain(value: str) -> IntelligenceDomain:
    key = value.strip().casefold()
    try:
        return BY_ID[ALIASES[key]]
    except KeyError as exc:
        raise KeyError(f"unknown intelligence domain: {value}") from exc


def domains_for_family(family: str) -> tuple[IntelligenceDomain, ...]:
    if family not in FAMILIES:
        raise KeyError(f"unknown intelligence family: {family}")
    return tuple(row for row in DOMAINS if row.family == family)


def taxonomy_summary() -> dict:
    return {
        "families": {
            family: [row.domain_id for row in domains_for_family(family)]
            for family in FAMILIES
        },
        "domain_count": len(DOMAINS),
        "sensitive_domains": [row.domain_id for row in DOMAINS if row.sensitive],
        "limitation": (
            "Taxonomy membership describes routing/analysis domains only. "
            "Executable capability requires a registered skill, governed tool/source, "
            "authorization, evidence contract, and qualification."
        ),
    }


def search_domains(query: str, *, limit: int = 20) -> tuple[IntelligenceDomain, ...]:
    """Lexically rank taxonomy entries for planner/knowledge discovery only."""
    import re
    terms = set(re.findall(r"[a-z0-9]+", query.casefold()))
    if not terms:
        return DOMAINS[:max(0, min(limit, len(DOMAINS)))]
    ranked = []
    for row in DOMAINS:
        haystack = " ".join((row.domain_id, row.title, row.family, *row.aliases)).casefold()
        tokens = set(re.findall(r"[a-z0-9]+", haystack))
        score = len(terms & tokens)
        if score:
            ranked.append((score, row.domain_id, row))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return tuple(item[2] for item in ranked[:max(0, min(limit, 100))])
