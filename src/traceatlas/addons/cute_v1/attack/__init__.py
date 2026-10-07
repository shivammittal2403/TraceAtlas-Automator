"""Lazy compatibility exports for the supplied ATT&CK source.

The original initializer eagerly imported four files absent from its own archive.
Existing symbols remain available; missing source implementations remain gaps.
No update, collection or persistence operation is invoked on package import.
"""
from importlib import import_module

_EXPORTS = {'AttackVersion': ('version', 'AttackVersion'), 'CURRENT_KNOWN_VERSIONS': ('version', 'CURRENT_KNOWN_VERSIONS'), 'pin_version': ('version', 'pin_version'), 'AttackClient': ('client', 'AttackClient'), 'StixLoader': ('loader', 'StixLoader'), 'AttackUpdater': ('updater', 'AttackUpdater'), 'EnterpriseMatrix': ('enterprise', 'EnterpriseMatrix'), 'MobileMatrix': ('mobile', 'MobileMatrix'), 'IcsMatrix': ('ics', 'IcsMatrix'), 'TacticStore': ('tactics', 'TacticStore'), 'TechniqueStore': ('techniques', 'TechniqueStore'), 'SubtechniqueStore': ('subtechniques', 'SubtechniqueStore'), 'SoftwareStore': ('software', 'SoftwareStore'), 'GroupStore': ('groups', 'GroupStore'), 'CampaignStore': ('campaigns', 'CampaignStore'), 'MitigationStore': ('mitigations', 'MitigationStore'), 'DetectionGuideStore': ('detections', 'DetectionGuideStore'), 'ProcedureStore': ('procedures', 'ProcedureStore'), 'RelationshipStore': ('relationships', 'RelationshipStore'), 'AttackMapper': ('mapper', 'AttackMapper'), 'BehaviorMatcher': ('matcher', 'BehaviorMatcher'), 'AttackValidator': ('validator', 'AttackValidator'), 'ValidationResult': ('validator', 'ValidationResult'), 'AttackComparator': ('comparator', 'AttackComparator'), 'CoverageAnalyzer': ('coverage', 'CoverageAnalyzer'), 'MatrixBuilder': ('matrix', 'MatrixBuilder'), 'AttackGraph': ('graph', 'AttackGraph'), 'AttackTimeline': ('timeline', 'AttackTimeline')}
__all__ = ['AttackVersion', 'CURRENT_KNOWN_VERSIONS', 'pin_version', 'AttackClient', 'StixLoader', 'AttackUpdater', 'TacticStore', 'TechniqueStore', 'SubtechniqueStore', 'SoftwareStore', 'GroupStore', 'CampaignStore', 'MitigationStore', 'DetectionGuideStore', 'ProcedureStore', 'RelationshipStore', 'AttackMapper', 'BehaviorMatcher', 'AttackValidator', 'ValidationResult', 'AttackComparator', 'CoverageAnalyzer', 'MatrixBuilder']

def __getattr__(name):
    spec = _EXPORTS.get(name)
    if spec is None:
        raise AttributeError(name)
    module, symbol = spec
    try:
        return getattr(import_module("." + module, __name__), symbol)
    except ModuleNotFoundError as exc:
        raise AttributeError(f"{name} has no implementation in the supplied archive") from exc
