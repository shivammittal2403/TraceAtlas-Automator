"""Project-wide constants."""

DEFAULT_TENANT_ID = "default"
MAX_OBJECTIVE_LENGTH = 4096
MIN_CONFIDENCE_FOR_CLAIM = 0.5
EVIDENCE_HASH_ALGORITHM = "sha256"
HTTP_TIMEOUT_SECONDS = 30
USER_AGENT = f"TraceAtlas-Automator/{__import__('traceatlas.addons.osint_v1.version', fromlist=['__version__']).__version__}"
