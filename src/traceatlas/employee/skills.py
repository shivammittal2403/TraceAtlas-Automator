"""Versioned analyst procedures, not claims of unrestricted provider access."""
from __future__ import annotations

import re

REFERENCES = {
    "wstg": {"title": "OWASP Web Security Testing Guide", "url": "https://owasp.org/projects/web-security-testing-guide"},
    "attack": {"title": "MITRE ATT&CK", "url": "https://attack.mitre.org/"},
    "nist-testing": {"title": "NIST SP 800-115: Technical Guide to Information Security Testing", "url": "https://csrc.nist.gov/pubs/sp/800/115/final"},
    "nist-forensics": {"title": "NIST SP 800-86: Integrating Forensic Techniques", "url": "https://csrc.nist.gov/pubs/sp/800/86/final"},
    "stix": {"title": "OASIS STIX 2.1", "url": "https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html"},
    "nvd": {"title": "NVD Vulnerability API", "url": "https://nvd.nist.gov/developers/vulnerabilities"},
    "kev": {"title": "CISA Known Exploited Vulnerabilities", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
    "epss": {"title": "FIRST EPSS", "url": "https://www.first.org/epss/"},
    "rdap": {"title": "ICANN RDAP", "url": "https://www.icann.org/rdap"},
    "asvs": {"title": "OWASP ASVS", "url": "https://owasp.org/www-project-application-security-verification-standard/"},
    "api": {"title": "OWASP API Security", "url": "https://owasp.org/www-project-api-security/"},
    "llm": {"title": "OWASP GenAI Security Project", "url": "https://genai.owasp.org/"},
}

# These original procedures use references for methodology; they are not copied
# source text, professional certifications, or new executable scanner adapters.
_ROWS = [
    ("scope", "Scope and rules of engagement", "both", "scope authorization permission mandate pt pentest", "nist-testing",
     "Record exact assets, owners, permitted actions and expiry;Separate passive research from active validation;Document stop conditions and who can approve changes", "Written scope and authorized asset list"),
    ("source-verification", "Source verification", "both", "source verify provenance fact evidence osint", "nist-forensics",
     "Record publisher and original record;Separate publication, observation and collection times;Find an independent corroboration or report the gap", "Original source and acquisition timestamp"),
    ("domain", "Domain and registration research", "osint", "domain dns rdap whois registration subdomain infrastructure", "rdap",
     "Collect exact domain registration and DNS observations;Record resolver and record time;Treat shared hosting as a hypothesis rather than ownership", "DNS/RDAP observations", ("dns", "rdap", "wayback")),
    ("exposure", "Passive internet exposure triage", "both", "ip ports service exposure shodan censys asset", "attack",
     "Check passive service observation dates;Compare findings to the authorized asset inventory;Request scoped validation before declaring a service vulnerable", "Dated service metadata", ("internetdb", "rdap")),
    ("archives", "Website history", "osint", "archive history wayback website change timeline", "nist-forensics",
     "Distinguish index records from captured content;Compare timestamps and content hashes;Preserve capture gaps and missing snapshots", "Archive capture/index references", ("wayback",)),
    ("social", "Public and consented social evidence", "osint", "social profile account instagram linkedin tiktok facebook", "nist-forensics",
     "Use permitted APIs or approved exports;Keep platform IDs and renamed handles;Record uncertainty before associating accounts", "Source-specific profile IDs and timestamps"),
    ("username", "Username ambiguity review", "osint", "username identity account correlation alias", "nist-forensics",
     "Compare stable IDs and explicit links;Check namesakes and recycled handles;Send candidate matches to human review", "Independent linking evidence"),
    ("corporate", "Corporate records research", "osint", "company business director organization ownership registry", "nist-forensics",
     "Match jurisdiction and registration identifier;Read filing date and ownership period;Separate same-name records until corroborated", "Official registry IDs and dated filings"),
    ("geo", "Geographic context", "osint", "map geo location geography landmark", "nist-forensics",
     "Record location source and granularity;Compare public landmarks and capture dates;Keep approximate location separate from exact attribution", "Public geographic evidence with uncertainty"),
    ("media", "Media provenance", "osint", "image video audio exif metadata media deepfake", "nist-forensics",
     "Preserve originals and compute hashes;Inspect metadata and manipulation limitations;Link observations to frames or time spans", "Original media hash and analysis method"),
    ("cti", "Threat intelligence triage", "both", "threat indicator ioc malware ransomware cti", "stix",
     "Check indicator type, first/last seen and expiry;Track upstream feed lineage and retractions;Separate published actor claims from corroborated incidents", "Dated indicators and source lineage"),
    ("cve", "Vulnerability applicability", "pt", "cve vulnerability nvd version cpe patch", "nvd",
     "Identify exact product and version;Check affected ranges and configuration prerequisites;Record applicability as unknown when inventory is missing", "Vendor advisory and deployed version", ("nvd",)),
    ("prioritization", "Vulnerability prioritization", "pt", "risk priority epss kev severity impact", "epss",
     "Combine asset impact, exposure and applicability;Keep exploitation evidence distinct from prediction;Record why a remediation is prioritized", "Asset context plus dated KEV/EPSS and advisory references"),
    ("web-config", "Web configuration assessment", "pt", "web header tls configuration http server", "wstg",
     "Review authorized request/response evidence;Check exposed metadata and transport configuration;Propose a bounded reproduction and retest", "HTTP/TLS evidence from an authorized assessment"),
    ("authn", "Authentication review", "pt", "authentication login mfa password session", "asvs",
     "Map login and recovery flows;Review session lifecycle with test accounts;Describe expected control and the observed deviation", "Approved test accounts and captured control behavior"),
    ("authz", "Authorization and tenant isolation", "pt", "authorization idor bola tenant rls access", "api",
     "Define roles and object ownership;Compare approved cross-role test cases;Verify rejected reads, writes and exports", "Role matrix and isolated test-tenant fixtures"),
    ("input", "Input and output handling", "pt", "injection xss sqli ssrf input output validation", "wstg",
     "Map untrusted input to sensitive operations;Review encoding and parameterization;Design non-destructive proof and regression cases", "Code path or controlled request/response evidence"),
    ("api", "API abuse review", "pt", "api graphql rest quota rate limit webhook", "api",
     "Inventory exposed operations and identities;Review quotas, replay and object access;Record missing controls and testable acceptance criteria", "API contract and approved fixtures"),
    ("cloud", "Cloud and storage exposure", "both", "cloud bucket s3 storage saas public exposure", "asvs",
     "Attribute assets before collection;Review permitted storage and access metadata;Separate discoverability from unauthorized readability", "Owned inventory and access policy evidence"),
    ("supply-chain", "Repository and dependency review", "pt", "github repository package dependency supply chain secret", "asvs",
     "Pin repository and commit;Review lockfiles, provenance and advisory applicability;Redact secret values and never test recovered credentials", "Commit-linked source and dependency versions"),
    ("ai-security", "AI application review", "pt", "ai llm prompt agent rag model injection", "llm",
     "Map retrieved content, model output and tool authority;Test indirect instructions with synthetic fixtures;Enforce permissions and citation validation outside the model", "Tool permissions and controlled injection fixtures"),
    ("scanner-review", "Scanner finding validation", "pt", "scanner nuclei zap nikto finding false positive", "nist-testing",
     "Record scanner version, scope and template;Check reproducibility and false positives;Attach analyst-approved remediation and retest conditions", "Original scanner output and authorized reproduction"),
    ("timeline", "Timeline reconstruction", "both", "timeline chronology time sequence incident", "nist-forensics",
     "Normalize timezone without replacing source time;Mark unknown or conflicting dates;Avoid inferring causality from event order alone", "Timestamped observations with timezone basis"),
    ("contradictions", "Competing hypothesis analysis", "both", "hypothesis scenario contradiction conflicting alternative", "nist-forensics",
     "List supporting and opposing observations;Generate benign and adverse explanations;Identify the next discriminating piece of evidence", "Evidence references for every analytical claim"),
    ("breach", "Organizational exposure summaries", "osint", "breach leak credential exposure dark web", "stix",
     "Use approved redacted metadata;Verify organization attribution and source dates;Prioritize protective action without retrieving reusable secrets", "Authorized exposure summary and provenance"),
    ("research", "Methodology and research retrieval", "both", "research paper knowledge learn methodology", "nist-testing",
     "Retrieve relevant methodology and research metadata;Check source, date and applicability;Keep literature separate from case-specific evidence", "Citable primary references and version/date"),
    ("report", "Decision brief and report", "both", "report decision brief recommendation insight", "nist-testing",
     "Separate observations, interpretation and unanswered questions;Link recommendations to cited evidence;Record the human decision and rationale", "Evidence-linked brief and decision journal"),
    ("monitor", "Change and coverage monitoring", "both", "monitor change alert freshness coverage", "stix",
     "Compare stable evidence fields;Differentiate changed evidence from provider failure;Route material changes for human review", "Versioned baseline and new observation timestamps"),
]


def skill_catalog(query: str = "", mode: str | None = None) -> list[dict]:
    terms = set(re.findall(r"[\w-]+", query.casefold()))
    result = []
    for row in _ROWS:
        key, title, scope, keywords, reference, steps, required, *sources = row
        if mode and scope not in {"both", mode}:
            continue
        score = len(terms & set(re.findall(r"[\w-]+", f"{title} {keywords}".casefold())))
        if terms and not score and key not in {"scope", "source-verification", "report"}:
            continue
        result.append({"id": key, "title": title, "mode": scope, "version": 1,
                       "steps": steps.split(";"), "required_evidence": required,
                       "reference_ids": [reference], "collection_sources": list(sources[0]) if sources else [],
                       "implementation": "analyst-procedure", "relevance": score})
    return sorted(result, key=lambda item: (-item["relevance"], item["id"]))
