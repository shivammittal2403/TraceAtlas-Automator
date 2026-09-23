from __future__ import annotations

import hashlib
import re
from typing import Any

from ..policy import PolicyError


BSSID_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
SHA1_RE = re.compile(r"^[0-9A-Fa-f]{40}$")


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


def require_sensitive_policy(*, authorized: bool, allow_sensitive: bool,
                             lawful_purpose: str, attestations: dict[str, bool],
                             required: tuple[str, ...]) -> None:
    if not authorized or not allow_sensitive:
        raise PolicyError(
            "Sensitive workflow requires both --authorized and --allow-sensitive"
        )
    if len(lawful_purpose.strip()) < 12:
        raise PolicyError("Record a specific lawful purpose of at least 12 characters")
    missing = [name for name in required if not attestations.get(name)]
    if missing:
        raise PolicyError("Missing required attestation(s): " + ", ".join(missing))


def validate_bssid(value: str) -> str:
    value = value.strip().upper().replace("-", ":")
    if not BSSID_RE.fullmatch(value):
        raise PolicyError("BSSID must be an exact 12-hex MAC address")
    # Multicast identifiers are not valid individual access-point seeds.
    first = int(value.split(":", 1)[0], 16)
    if first & 1:
        raise PolicyError("Multicast BSSID values are not accepted")
    return value


def validate_sha1(value: str) -> str:
    value = value.strip().upper()
    if not SHA1_RE.fullmatch(value):
        raise PolicyError("Provide a 40-character SHA-1 hash, never a plaintext password")
    return value


def minimize_breach(record: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "Name", "Title", "Domain", "BreachDate", "AddedDate", "ModifiedDate",
        "PwnCount", "DataClasses", "IsVerified", "IsFabricated", "IsSensitive",
        "IsRetired", "IsSpamList", "IsMalware", "IsStealerLog",
    }
    return {key: record[key] for key in allowed if key in record}
