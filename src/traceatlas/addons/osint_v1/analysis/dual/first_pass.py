"""Pass 1 — PRIMARY INTELLIGENCE ANALYST entry point (§4)."""
from traceatlas.addons.osint_v1.analysis.prompts import PRIMARY_SYSTEM  # noqa: F401
from traceatlas.addons.osint_v1.analysis.engine import DualAnalysisEngine  # noqa: F401


def run_primary(engine: DualAnalysisEngine, ctx, model: str | None = None):
    from traceatlas.addons.osint_v1.analysis.deterministic_grounding import ground_pass
    pass_obj = engine._run_pass("primary", PRIMARY_SYSTEM, ctx,
                                model or engine.primary_model)
    return pass_obj, ground_pass(pass_obj, ctx)
