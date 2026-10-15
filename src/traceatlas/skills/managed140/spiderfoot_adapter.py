"""Read-only importer for SpiderFoot 4.0 JSON exports (not a scan launcher)."""
from __future__ import annotations
import json

_MAX_EVENTS = 2000
_MAX_TEXT = 4096
_EVENT_FIELD = {
    "DOMAIN_NAME": ("DOMAININT", "domain"),
    "INTERNET_NAME": ("DOMAININT", "domain"),
    "IP_ADDRESS": ("IPINT", "ip"),
    "EMAILADDR": ("EMAILINT", "from_addr"),
    "URL_INTERNAL": ("WEBINT", "url"),
    "URL_EXTERNAL": ("WEBINT", "url"),
    "COMPANY_NAME": ("CORPINT", "company"),
    "SSL_CERTIFICATE": ("CERTINT", "subject"),
}
_BLOCKED = ("PASSWORD", "CREDENTIAL", "PRIVATE", "SECRET", "TOKEN", "API_KEY")

def imported_records(export, *, scan_id="uploaded-export", source_ref=None):
    """Return evidence records per TraceAtlas domain; never infer live proof or source independence."""
    if isinstance(export, str):
        export = json.loads(export)
    if isinstance(export, dict):
        export = export.get("events", export.get("data", []))
    if not isinstance(export, list) or len(export) > _MAX_EVENTS:
        raise ValueError("Expected bounded SpiderFoot JSON event list")
    grouped = {}
    for index, event in enumerate(export):
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or event.get("eventType") or "").upper()
        if any(word in event_type for word in _BLOCKED):
            continue
        mapping = _EVENT_FIELD.get(event_type)
        if not mapping:
            continue
        domain, field = mapping
        value = event.get("data")
        if not isinstance(value, str) or not value or len(value) > _MAX_TEXT:
            continue
        module = str(event.get("module") or "unknown")[:80]
        grouped.setdefault(domain, []).append({
            "source_id": source_ref or ("spiderfoot:" + str(scan_id) + ":" + module),
            "independence_group": "spiderfoot-export:" + str(scan_id),
            "observed_at": str(event.get("generated") or ""),
            "data": {field: value, "source_name": "SpiderFoot v4.0", "source_ref": str(index)}
        })
    return grouped
