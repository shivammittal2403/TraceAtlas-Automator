from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse


class PolicyError(ValueError):
    """Raised when a requested action violates an execution policy."""


@dataclass(frozen=True)
class Target:
    kind: str
    value: str


EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")
USERNAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def validate_target(kind: str, value: str) -> Target:
    value = value.strip()
    if not value:
        raise PolicyError("Target cannot be empty")
    if kind == "email" and not EMAIL.fullmatch(value):
        raise PolicyError("Invalid email address")
    if kind == "domain" and not DOMAIN.fullmatch(value):
        raise PolicyError("Invalid domain name")
    if kind == "ip":
        ip_address(value)
    if kind == "url":
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PolicyError("Only valid HTTP(S) URLs are allowed")
    if kind == "file" and not Path(value).is_file():
        raise PolicyError("File target does not exist")
    if kind == "path" and not Path(value).exists():
        raise PolicyError("Local path target does not exist")
    if kind == "username" and not USERNAME.fullmatch(value):
        raise PolicyError("Invalid username syntax")
    return Target(kind, value)


def require_authorization(method_risk: str, authorized: bool) -> None:
    if method_risk in {"medium", "high"} and not authorized:
        raise PolicyError(
            "This workflow needs an explicit --authorized confirmation. "
            "Use it only for lawful research with a documented purpose."
        )


def redact(value: str) -> str:
    if EMAIL.fullmatch(value):
        local, domain = value.split("@", 1)
        return f"{local[:2]}***@{domain}"
    return value
