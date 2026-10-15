"""OTINT: offline supplied-evidence adapter.

Not a qualified collector; cannot access networks or execute external tools.
"""
from ..engine import analyze as _analyze
CODE = "OTINT"

def run(payload, *, authorized=False, case_id="local"):
    return _analyze(CODE, payload, authorized=authorized, case_id=case_id)
