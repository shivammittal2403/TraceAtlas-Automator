"""Offline research intelligence built from audited bibliographic metadata."""

from .analysis import explainable_entity_match, temporal_analysis
from .catalog import ResearchCatalog

__all__ = ["ResearchCatalog", "explainable_entity_match", "temporal_analysis"]
