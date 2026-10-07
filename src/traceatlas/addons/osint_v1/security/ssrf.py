"""SSRF protection: refuse non-HTTP schemes and private destinations by default."""

from __future__ import annotations

from traceatlas.addons.osint_v1.core.validation import is_http_url
from traceatlas.addons.osint_v1.exceptions import PolicyViolation
from traceatlas.addons.osint_v1.security.url_policy import is_private_host


def assert_egress_allowed(url: str, *, allow_private: bool = False) -> None:
    if not is_http_url(url):
        raise PolicyViolation(f"non-http(s) URL refused: {url!r}")
    if not allow_private and is_private_host(url):
        raise PolicyViolation(f"private/internal destination refused (SSRF guard): {url!r}")
