"""Canonical TraceAtlas skill taxonomy and registry.

This package is additive: existing employee/workforce execution remains canonical
until individual skills are promoted into governed executable adapters.
"""
from .contracts import SkillDefinition, SkillResult
from .domains import DOMAINS, FAMILIES, IntelligenceDomain, resolve_domain, taxonomy_summary
from .registry import SkillRegistry

__all__ = [
    "SkillDefinition", "SkillResult", "SkillRegistry",
    "DOMAINS", "FAMILIES", "IntelligenceDomain", "resolve_domain", "taxonomy_summary",
]
