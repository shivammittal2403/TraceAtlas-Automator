from __future__ import annotations

from .models import Method


_ROWS = [
    (0,"photo-geolocation","Geolocate a photo from visual clues","Extract clues, form hypotheses and corroborate against maps.","Beginner",20,"assisted",("file",),("file_metadata",),"medium"),
    (1,"reverse-image","Verify a photo with reverse image search","Trace earlier appearances, variants and context.","Beginner",25,"assisted",("file","url"),("file_metadata","search_queries"),"low"),
    (2,"username-pivot","Find accounts linked to a username","Pivot across platforms while controlling for namesakes.","Beginner",20,"partial",("username",),("username_links",),"medium"),
    (3,"email-investigation","Investigate an email address","Validate format and review lawful exposure signals.","Intermediate",45,"partial",("email",),("email_basic","search_queries"),"medium"),
    (4,"domain-map","Map a domain's infrastructure","Enumerate DNS, certificates, hosts and ownership.","Beginner",30,"high",("domain",),("dns","tls","http"),"medium"),
    (5,"safe-environment","Set up a safe OSINT research environment","Audit separation, evidence and network hygiene.","Beginner",20,"checklist",("text",),("environment_check",),"low"),
    (6,"phone-investigation","Investigate a phone number","Assess numbering metadata and public associations without contact.","Intermediate",35,"assisted",("phone",),("search_queries",),"high"),
    (7,"video-verification","Verify a video","Extract key facts and test source, time and place.","Beginner",15,"assisted",("file","url"),("file_metadata",),"medium"),
    (8,"web-archive","Recover deleted or changed web pages","Generate archive pivots and preserve public content.","Intermediate",45,"partial",("url",),("archive_links","http"),"low"),
    (9,"company-research","Research a company","Validate identity, ownership, operations and reputation.","Beginner",20,"assisted",("text","domain"),("search_queries","dns"),"medium"),
    (10,"file-metadata","Extract and analyze file metadata","Hash and interpret embedded metadata carefully.","Advanced",50,"high",("file",),("file_metadata",),"low"),
    (11,"crypto-trace","Trace a cryptocurrency transaction","Structure public-ledger observations without attribution.","Beginner",25,"assisted",("crypto",),("search_queries",),"high"),
    (12,"advanced-search","Use advanced search operators","Build precise and reproducible queries.","Intermediate",30,"high",("text","domain","email","username"),("search_queries",),"low"),
    (13,"event-monitoring","Monitor an unfolding event in real time","Collect signals without amplifying unverified claims.","Beginner",20,"partial",("text","url"),("search_queries","http"),"medium"),
    (14,"transport-tracking","Track a flight, ship or vehicle","Correlate public tracking identifiers and time windows.","Intermediate",35,"assisted",("text",),("search_queries",),"high"),
    (15,"social-account","Investigate a social media account","Analyze authenticity, activity and content patterns.","Beginner",40,"assisted",("username","url"),("username_links","http"),"medium"),
    (16,"digital-footprint","Reduce your own digital footprint","Inventory exposure and prioritize lawful removals.","Beginner",20,"assisted",("email","username","domain"),("search_queries","username_links"),"medium"),
    (17,"website-legitimacy","Check whether a website is legitimate","Assess identity, infrastructure and transaction risk.","Intermediate",30,"high",("url","domain"),("dns","tls","http"),"low"),
    (18,"research-persona","Create a separated research persona","Produce a compliant setup checklist without impersonation.","Intermediate",20,"checklist",("text",),("environment_check",),"medium"),
    (19,"ip-investigation","Investigate an IP address","Map allocation context, reverse DNS and related infrastructure.","Beginner",20,"partial",("ip",),("ip_basic",),"medium"),
    (20,"evidence-preservation","Preserve and document OSINT evidence","Capture provenance, timestamps, hashes and custody history.","Advanced",45,"high",("file","url"),("file_metadata","http"),"low"),
    (21,"social-network-map","Map a social network","Model entities and relationships without overstating edges.","Advanced",35,"assisted",("text",),("search_queries",),"high"),
    (22,"dark-web-research","Research the dark web safely","Use indexed metadata only with ownership and harm controls.","Intermediate",20,"partial",("domain",),(),"high"),
    (23,"website-fingerprint","Fingerprint a website's technology","Identify stack, headers and public technical identifiers.","Advanced",25,"high",("url","domain"),("http","tls"),"medium"),
    (24,"chronolocation","Chronolocate a photo or video","Estimate time from visual and contextual evidence.","Beginner",20,"assisted",("file",),("file_metadata",),"medium"),
    (25,"osint-monitoring","Automate OSINT monitoring","Create repeatable snapshots with deduplication and review gates.","Advanced",30,"high",("url","domain","text"),("http","dns","search_queries"),"medium"),
    (26,"breach-analysis","Analyze a data breach responsibly","Summarize authorized artifacts and verified-domain exposure without copying leaked rows.","Intermediate",25,"partial",("file","email","domain"),(),"high"),
    (27,"misinformation","Debunk viral misinformation","Trace origin and test each claim component.","Beginner",30,"assisted",("text","url","file"),("search_queries","http","file_metadata"),"medium"),
    (28,"public-records","Search public records for a person","Use official records with identity-resolution safeguards.","Intermediate",60,"assisted",("text",),("search_queries",),"high"),
    (29,"person-profile","Build a sourced OSINT profile on a person","Find consented public professional candidates with uncertainty and harm controls.","Intermediate",30,"assisted",("text",),(),"high"),
    (30,"bot-detection","Detect fake or bot social accounts","Evaluate profile, content, timing and coordination signals.","Intermediate",25,"assisted",("username","url"),("username_links","http"),"medium"),
    (31,"email-headers","Trace an email's origin from headers","Parse routing and authentication without trusting display fields.","Intermediate",40,"high",("file",),("email_headers",),"low"),
    (32,"crypto-scam","Investigate a cryptocurrency scam","Map wallet, contract and promotional infrastructure.","Beginner",30,"assisted",("crypto","domain","url"),("search_queries","dns","http"),"high"),
    (33,"credential-monitoring","Monitor for leaked credentials","Use k-anonymity and verified-domain checks without retrieving credentials.","Advanced",30,"partial",("email","domain"),(),"high"),
    (34,"wifi-geolocation","Geolocate a Wi-Fi network","Look up an owned exact BSSID and retain only coarse location.","Beginner",25,"partial",("text",),(),"high"),
    (35,"news-credibility","Verify the credibility of a news source","Evaluate ownership, sourcing and corroboration.","Advanced",45,"assisted",("url","domain"),("dns","tls","http","search_queries"),"low"),
    (36,"mobile-app","Analyze a mobile app for OSINT","Inspect package metadata and identifiers statically.","Intermediate",35,"partial",("file",),("file_metadata",),"medium"),
    (37,"timeline","Build an investigation timeline","Normalize timestamps and expose gaps and conflicts.","Intermediate",50,"high",("file","text"),("timeline",),"low"),
    (38,"business-due-diligence","Conduct business due diligence","Assess ownership, reputation and cyber footprint.","Intermediate",30,"assisted",("text","domain"),("search_queries","dns","tls","http"),"medium"),
    (39,"osint-report","Write an evidence-based OSINT report","Separate facts, assessments, gaps and confidence.","Intermediate",30,"high",("text",),(),"low"),
]

METHODS = tuple(Method(*row) for row in _ROWS)
BY_ID = {m.id: m for m in METHODS}
BY_SLUG = {m.slug: m for m in METHODS}


def get_method(value: str | int) -> Method:
    try:
        key = int(value)
    except (TypeError, ValueError):
        method = BY_SLUG.get(str(value))
    else:
        method = BY_ID.get(key)
    if method is None:
        raise KeyError(f"Unknown method: {value}")
    return method
