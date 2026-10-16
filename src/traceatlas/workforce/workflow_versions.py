"""Approved investigation semantics shared by planning, execution and replay."""

CURRENT_WORKFLOW_VERSION = "evidence-investigation/1.5.0"
LEGACY_WORKFLOW_VERSION = "evidence-investigation/1.4.0"
SUPPORTED_WORKFLOW_VERSIONS = frozenset({LEGACY_WORKFLOW_VERSION, CURRENT_WORKFLOW_VERSION})
WORKFLOW_CONSTRAINT_PREFIX = "workflow-version:"
