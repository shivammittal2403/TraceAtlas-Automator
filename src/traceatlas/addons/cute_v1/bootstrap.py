
"""traceatlas.addons.cute_v1.bootstrap - Application composition root.

Wires together registries, stores and engines into an `Application` object
that API, CLI and workers all share. No globals; everything explicit.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .config import Settings, load_settings
from .logging import configure_logging, get_logger


@dataclass(slots=True)
class Application:
    settings: Settings
    source_registry: object = None
    employee_registry: object = None
    evidence_store: object = None
    planner: object = None
    engine: object = None
    reasoner: object = None
    verification_engine: object = None
    contradiction_engine: object = None
    ai_gateway: object = None
    logger: object = field(default_factory=lambda: get_logger("app"))

    @property
    def ready(self) -> bool:
        return all(x is not None for x in (
            self.source_registry, self.evidence_store, self.planner,
            self.engine, self.reasoner, self.verification_engine))


def build_application(settings: Settings | None = None) -> Application:
    settings = settings or load_settings()
    configure_logging(settings.log_level)
    app = Application(settings=settings)

    from traceatlas.addons.cute_v1.sources.registry import SourceRegistry
    from traceatlas.addons.cute_v1.evidence.store import EvidenceStore
    from traceatlas.addons.cute_v1.planning.planner import Planner
    from traceatlas.addons.cute_v1.investigation.engine import InvestigationEngine
    from traceatlas.addons.cute_v1.reasoning.engine import ReasoningEngine
    from traceatlas.addons.cute_v1.verification.engine import VerificationEngine
    from traceatlas.addons.cute_v1.contradictions.engine import ContradictionEngine
    from traceatlas.addons.cute_v1.employees.registry import EmployeeRegistry
    from traceatlas.addons.cute_v1.ai.gateway import AIGateway

    app.source_registry = SourceRegistry.load_default()
    app.employee_registry = EmployeeRegistry.default()
    app.evidence_store = EvidenceStore(root=settings.storage.local_dir)
    app.ai_gateway = AIGateway(settings.ai)
    app.planner = Planner(app.source_registry)
    app.reasoner = ReasoningEngine()
    app.verification_engine = VerificationEngine(app.source_registry)
    app.contradiction_engine = ContradictionEngine()
    app.engine = InvestigationEngine(app)
    app.logger.info("application built", extra={"sources": len(app.source_registry.all())})
    return app
