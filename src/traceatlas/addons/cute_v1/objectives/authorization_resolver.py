"""traceatlas.addons.cute_v1.objectives.authorization_resolver - Attach/validate authorization."""
from __future__ import annotations

from traceatlas.addons.cute_v1.core.authorization import Authorization
from traceatlas.addons.cute_v1.exceptions import AuthorizationRequiredError


def require_valid(authorization: Authorization | None) -> Authorization:
    if authorization is None or not authorization.is_valid():
        raise AuthorizationRequiredError(
            "TraceAtlas will not plan or execute collection without a valid, "
            "unexpired authorization record (granted_by, basis, scopes).")
    return authorization
