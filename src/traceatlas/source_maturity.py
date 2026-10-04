"""Canonical, evidence-honest source maturity vocabulary.

Health and operational failures are represented separately from maturity. Older
internal labels are accepted only at this boundary and normalized before they
reach a source manifest or summary.
"""

MATURITY_STATES = (
    "DISCOVERED",
    "CATALOGUED",
    "TERMS_REVIEWED",
    "CONNECTOR_CODED",
    "CONFIGURED",
    "LIVE_TESTED",
    "LIVE_VERIFIED",
    "PRODUCTION_QUALIFIED",
    "DEGRADED",
    "DISABLED",
    "DEPRECATED",
)

SOURCE_QUALIFICATION_GATES = frozenset({
    "documentation", "manifest", "capabilities", "connector", "terms", "license",
    "authentication", "configured", "live_request", "normalization", "evidence",
    "provenance", "failure", "fallback", "rate_limits", "cost", "security",
    "schema_drift", "tests", "canary", "health", "operational_owner", "runbook",
})

LIVE_VERIFICATION_GATES = SOURCE_QUALIFICATION_GATES - frozenset({"operational_owner", "runbook"})

_LEGACY_STATES = {
    "DOCUMENTED": "CATALOGUED",
    "CONNECTOR_IMPLEMENTED": "CONNECTOR_CODED",
    "BROKEN": "DEGRADED",
}


def normalize_maturity(state: str) -> str:
    """Return an allowed maturity state or reject an unknown label."""
    normalized = _LEGACY_STATES.get(state, state)
    if normalized not in MATURITY_STATES:
        raise ValueError("unknown source maturity state")
    return normalized


def maturity_counts(states):
    """Count every maturity explicitly, including states whose count is zero."""
    counts = {state: 0 for state in MATURITY_STATES}
    for state in states:
        counts[normalize_maturity(state)] += 1
    return counts
