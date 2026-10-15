# TraceAtlas Module-Only Recovery (2026-10-15)

This is a provenance-preserving, isolated module archive added under extras/.
It does not overwrite the canonical Python modules, Manager, Team Leads, Skills,
Fact Gate, GUI or production entrypoints.

The local recovery extracted 136 isolated Python segments plus one validator
from the 419,712-line submitted source. In the prior local audit, 136/136
module imports and 33/33 invoked sample workflows passed. The package also
passed Python compilation for 137/137 files. Those checks do NOT prove
every function works. Thirty-six sections in the original source were truncated.

GitHub package SHA-256:
646d1416f23e9d26ab45026eedf44427e51f05b7fd358290768822fdc11c173d

Original submitted source SHA-256:
5a5f51623f7ad13b0a40b12dcb05110da20262c1ae9d387bed290cd44555add5

Two AWS-key-shaped synthetic CODEINT fixtures are redacted in the published
modules. The unaltered original source is retained outside this GitHub package.

GitHub connector transport required 75 base64 chunks. restore.py reconstructs
the exact safe ZIP only after SHA-256 verification, then checks per-module
hashes and Python syntax without running modules or calling the network.

From repository root:

    python extras/osint_module_recovery_20261015/restore.py
    python extras/osint_module_recovery_20261015/restore.py --extract
    python extras/osint_module_recovery_20261015/_extracted/modules/_validate_modules.py --json
    python -m compileall -q extras/osint_module_recovery_20261015/_extracted/modules

The default command only verifies; --extract writes to a new _extracted folder.
No existing files will be overwritten. _extracted is ignored by Git.

This is a reviewable SOURCE RECOVERY, not a live API connector installation or
an enterprise certification. Production integration must separately review
licensing, original truncations, safety, test coverage, exact module identity
and canonical case/evidence authorization before any execution.
