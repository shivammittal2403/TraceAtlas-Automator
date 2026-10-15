"""The requested 140-label research taxonomy, mapped to existing contracts.

Routes retain the backend's actual capability mode. A parent route is explicitly
broader than the requested label and is never advertised as a dedicated collector.
"""
from __future__ import annotations

from .addons.intelligence_v1.registry import catalog

GROUP_NAMES = {
    1: "DISCOVERY / OSINT",
    2: "HUMAN / SOCIAL / INFORMATION",
    3: "CYBER / THREAT",
    4: "NETWORK / INFRASTRUCTURE",
    5: "SOFTWARE / ENGINEERING",
    6: "MEDIA / EVIDENCE / VERIFICATION",
    7: "CORPORATE / ECONOMIC",
    8: "FRAUD / EXPOSURE",
    9: "SUPPLY CHAIN / TRANSPORT",
    10: "RESEARCH / GOVERNMENT / POLICY",
}

GROUP_TERMS = {
    1: "OSINT WEBINT SEARCHINT DORKINT ARCHIVEINT NEWSINT DATASETINT EVENTINT TIMELINEINT",
    2: "SOCMINT HUMINT COMINT DECEPTIONINT TEXTINT LANGINT NARRATIVEINT DISINFOINT MISINFOINT PROPINT SENTIMENTINT MEMEINT FORUMINT MESSENGERINT EMAILINT PHONEINT USERNAMEINT IDENTITYINT PERSONAINT RELATIONINT NETWORKINT",
    3: "CYBINT CTI IOCINT TTPINT THREATACTORINT CAMPAIGNINT MALINT EXPLOITINT VULNINT INCIDENTINT LOGINT DFIRINT HUNTINT DETECTIONINT",
    4: "SIGINT ELINT DOMAININT DNSINT IPINT ASNINT BGPINT NETINT INFRAINT CERTINT TLSINT CLOUDINT HOSTINT ROUTEINT CDNINT MAILINT",
    5: "TECHINT REPOINT PACKAGEINT SBOMINT DEPENDENCYINT CODEINT DEVINT CICDINT APPINT MOBILEINT IOTINT OTINT ICSINT APIINT CWEINT",
    6: "MASINT GEOINT IMINT VIDINT AUDINT DOCINT METADATAINT TRUSTINT SOURCEINT PROVENANCEINT CORROBORATIONINT CONTRADICTIONINT VERIFICATIONINT HYPOTHESISINT FALSIFICATIONINT",
    7: "FININT CORPINT ORGINT TRADEINT JOBINT OWNERSHIPINT PROCUREMENTINT CONTRACTINT ADDRESSINT PROPERTYINT ASSETINT TAXINT INSOLVENCYINT MNAINT MARKETINT COMPETITORINT CUSTOMERINT",
    8: "EXPOSUREINT BREACHINT CREDINT FRAUDINT SCAMINT PAYMENTINT CRYPTOINT MARKETPLACEINT BRANDINT ADINT COMPLAINTINT REPUTATIONINT",
    9: "SUPPLYCHAININT VENDORINT LOGISTICSINT TRANSPORTINT MARITIMEINT AVIATIONINT RAILINT",
    10: "ACADEMICINT REGINT LEGALINT SANCTIONSINT GOVINT POLICYINT DIPLOINT NGOINT EDUINT PATENTINT IPRINT STANDARDSINT RNDINT INNOVATIONINT",
}

LEGACY_ALIASES = {
    "ACADEMICINT": "accadmicint",
    "CTI": "ctiint",
    "EXPLOITINT": "expoitint",
    "GEOINT": "geomint",
    "IMINT": "imgmint",
    "MARITIMEINT": "maretineint",
    "MEMEINT": "memint",
    "PATENTINT": "patint",
    "PAYMENTINT": "payint",
    "RELATIONINT": "RELATIONSHIPINT",
    "SANCTIONSINT": "sanctionint",
    "VIDINT": "vedmint",
}

PARENT_ROUTES = (
    ("SEARCHINT DORKINT ARCHIVEINT", "osint", "Public-source collection planning; search and archive acquisition are not executed."),
    ("DATASETINT", "dataint", "Supplied dataset identity, provenance and quality; no dataset acquisition."),
    ("TEXTINT SENTIMENTINT", "langint", "Supplied language/text records; sentiment scoring is not validated."),
    ("MISINFOINT", "disinfoint", "Supplied claims and sources; no automatic truth or intent determination."),
    ("PROPINT", "narrativeint", "Supplied narratives and framing; propaganda classification is not verified."),
    ("FORUMINT", "socmint", "Public/social-source collection planning; no forum collector."),
    ("MESSENGERINT", "comint", "Communications collection planning; no message or private inbox collection."),
    ("PERSONAINT", "identityint", "Supplied persona/account assertions; personas remain distinct from legal identity."),
    ("NETWORKINT", "RELATIONSHIPINT", "Supplied relationship graphs; this route does not concern Internet infrastructure."),
    ("ASNINT BGPINT ROUTEINT", "netint", "Network evidence collection planning; no registry lookup or routing collector."),
    ("CERTINT TLSINT CDNINT", "infraint", "Infrastructure evidence collection planning; no certificate, TLS or CDN collector."),
    ("MAILINT", "dnsint", "DNS/mail-routing collection planning; no mailbox access or delivery testing."),
    ("CAMPAIGNINT", "ctiint", "Threat-context collection planning; no verified campaign clustering or attribution."),
    ("EXPOSUREINT", "breachint", "Exposure/breach evidence collection planning; no exposure-feed collection."),
    ("INCIDENTINT HUNTINT DETECTIONINT", "dfirint", "Defensive-evidence scope check; telemetry, hunting and detection are unconfigured."),
    ("DEPENDENCYINT", "packageint", "Supplied package, dependency and advisory records; no dependency acquisition."),
    ("CICDINT APIINT", "devint", "Development-record scope check; CI execution and API probing are unconfigured."),
    ("APPINT MOBILEINT", "techint", "Technical-evidence collection planning; no application or mobile-device collector."),
    ("OTINT ICSINT", "icsotint", "Shared ICS/OT scope check; no operational-device interaction."),
    ("CWEINT", "codeint", "Code-review scope check; weakness detection and CWE classification are unconfigured."),
    ("MARKETPLACEINT JOBINT", "scamint", "Scam-evidence collection planning; no marketplace or employment collector."),
    ("ADINT", "brandint", "Supplied brand and advertising claims; no ad-library collector."),
    ("COMPLAINTINT", "fraudint", "Supplied complaints and fraud records; allegations remain attributed and unverified."),
    ("TRUSTINT CORROBORATIONINT", "sourceint", "Supplied source reliability, provenance and independence; no automatic truth verdict."),
    ("VERIFICATIONINT HYPOTHESISINT", "evidenceint", "Supplied evidence review; no independent verification or hypothesis execution."),
    ("FALSIFICATIONINT", "contradictionint", "Supplied contradictions; no independent experiment or falsification verdict."),
    ("OWNERSHIPINT ADDRESSINT PROPERTYINT MNAINT", "corpint", "Corporate-record collection planning; no independent ownership, title or transaction verification."),
    ("CONTRACTINT", "procurementint", "Published procurement/contract collection planning; no private-contract collector."),
    ("TAXINT", "finint", "Public/submitted financial-record collection planning; no private tax-return collector."),
    ("INSOLVENCYINT", "legalint", "Published proceeding collection planning; current insolvency status is not verified."),
    ("POLICYINT DIPLOINT", "govint", "Official government-source collection planning; current policy/diplomatic status is not verified."),
    ("NGOINT", "orgint", "Organization-record collection planning; NGO registration is not verified."),
    ("EDUINT RNDINT INNOVATIONINT", "accadmicint", "Supplied academic/research records; accreditation, research validity and outcomes are not verified."),
    ("IPRINT", "patint", "Supplied patent records; other intellectual-property rights are outside this route."),
    ("STANDARDSINT", "techint", "Technical-document collection planning; no licensed-standard acquisition or certification."),
    ("COMPETITORINT CUSTOMERINT", "marketint", "Supplied market/customer-reference records; no independent entity discovery."),
    ("VENDORINT", "supplychainint", "Supply-chain collection planning; no independent vendor qualification."),
    ("LOGISTICSINT RAILINT", "transportint", "Supplied movement/transport records; no live dispatch, tracking or logistics-system access."),
    ("METADATAINT", "docint", "Supplied document-manifest metadata; embedded media extraction is not guaranteed."),
)

KNOWN_MODES = {"SUPPLIED_RECORD_ANALYSIS", "PLANNING_ONLY", "UNCONFIGURED_SCOPE_CHECK"}


def build_taxonomy(manifest):
    modules = manifest["modules"]
    by_id = {row["id"]: row for row in modules}
    by_upper = {row["id"].upper(): row["id"] for row in modules}
    if len(by_id) != len(modules) or len(by_upper) != len(modules):
        raise ValueError("Catalog module IDs must be unique")
    parents = {}
    for labels, module_id, scope in PARENT_ROUTES:
        for label in labels.split():
            if label in parents:
                raise ValueError("Duplicate parent route: " + label)
            parents[label] = (module_id, scope)

    result = {}
    for group_id, labels in GROUP_TERMS.items():
        for label in labels.split():
            if label in result:
                raise ValueError("Duplicate taxonomy label: " + label)
            if label in by_upper:
                module_id, kind = by_upper[label], "exact"
                scope = "Existing catalog entry; execution is limited to its catalog mode."
            elif label in LEGACY_ALIASES:
                module_id, kind = LEGACY_ALIASES[label], "legacy_alias"
                scope = "Legacy-named handler; its existing input schema and capability mode apply."
            elif label in parents:
                module_id, scope = parents[label]
                kind = "parent_discipline"
            else:
                raise ValueError("No route defined: " + label)
            if module_id not in by_id:
                raise ValueError("Route backend is absent from catalog: " + module_id)
            item = by_id[module_id]
            if item.get("mode") not in KNOWN_MODES:
                raise ValueError("Unknown execution mode: " + module_id)
            result[label] = {
                "requested_discipline": label,
                "canonical_id": module_id,
                "group_id": group_id,
                "group_name": GROUP_NAMES[group_id],
                "route_kind": kind,
                "dedicated_handler": kind != "parent_discipline",
                "scope_note": scope,
                "execution_mode": item["mode"],
                "live_verified": item.get("live_verified", False),
                "hosted_verified": item.get("hosted_verified", False),
                "module_sha256": item["file_sha256"],
            }
    return result


def resolve_route(label, manifest):
    if not isinstance(label, str):
        raise ValueError("Intelligence label must be text")
    label = label.strip().upper()
    routes = build_taxonomy(manifest)
    if label not in routes:
        raise ValueError("Unknown intelligence label: " + label)
    return routes[label]


def catalog_routes():
    return list(build_taxonomy(catalog()).values())


def get_route(label):
    return resolve_route(label, catalog())
