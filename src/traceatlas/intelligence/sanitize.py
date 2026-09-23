from __future__ import annotations

import hashlib
import json
import re
from typing import Any


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)")
SECRET_PARTS = ("password", "passwd", "secret", "token", "private_key", "api_key", "cookie")
PROHIBITED_PARTS = (
    "aadhaar", "aadhar", "ssn", "social_security", "passport", "government_id",
    "payment_card", "credit_card", "home_address", "exact_location",
    "gpslatitude", "gpslongitude", "latitude", "longitude",
)


def fingerprint(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def sanitize_text(text: str, limit: int = 20_000) -> str:
    text = text[:limit]
    text = EMAIL_RE.sub(lambda match: f"[EMAIL:{fingerprint(match.group(0).lower())[:12]}]", text)
    text = PHONE_RE.sub(lambda match: f"[PHONE:{fingerprint(match.group(0))[:12]}]", text)
    return text


def sanitize_record(value: Any, key: str = "", stats: dict[str, int] | None = None) -> Any:
    stats = stats if stats is not None else {"redacted": 0, "removed": 0, "truncated": 0}
    lowered = key.lower().replace("-", "_").replace(" ", "_")
    if any(part in lowered for part in PROHIBITED_PARTS):
        stats["removed"] += 1
        return {"removed": True, "reason": "data-minimization"}
    if any(part in lowered for part in SECRET_PARTS) and value not in (None, "", [], {}):
        stats["redacted"] += 1
        return {"redacted": True, "sha256": fingerprint(value)}
    if "email" in lowered and isinstance(value, str) and EMAIL_RE.fullmatch(value.strip()):
        stats["redacted"] += 1
        address = value.strip().lower()
        return {"redacted": True, "sha256": fingerprint(address), "domain": address.rsplit("@", 1)[1]}
    if any(part in lowered for part in ("phone", "mobile", "telephone")) and isinstance(value, str):
        stats["redacted"] += 1
        return {"redacted": True, "sha256": fingerprint(value), "last2": re.sub(r"\D", "", value)[-2:]}
    if isinstance(value, dict):
        return {str(k): sanitize_record(v, str(k), stats) for k, v in list(value.items())[:200]}
    if isinstance(value, list):
        if len(value) > 200:
            stats["truncated"] += len(value) - 200
        return [sanitize_record(item, key, stats) for item in value[:200]]
    if isinstance(value, str):
        if len(value) > 2_000:
            stats["truncated"] += 1
        return sanitize_text(value[:2_000], 2_000)
    return value
