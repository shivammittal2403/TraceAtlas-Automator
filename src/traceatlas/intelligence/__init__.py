"""Governed multi-source and AI-assisted intelligence workflows."""

from .ai import IntelligenceAnalyzer
from .hub import IntelligenceHub
from .media import MediaAnalyzer
from .sources import SOURCES, SourceSpec
from .orchestrator import CollectionOrchestrator
from .modules import MODULE_CATALOG, IntelligenceModule
from .contracts import ConnectorContract, connector_contracts, source_contract

__all__ = [
    "CollectionOrchestrator", "IntelligenceAnalyzer", "IntelligenceHub", "MediaAnalyzer",
    "SOURCES", "SourceSpec", "MODULE_CATALOG", "IntelligenceModule",
    "ConnectorContract", "connector_contracts", "source_contract",
]
