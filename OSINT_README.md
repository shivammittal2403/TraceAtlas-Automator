# OSINT Python: 140 requested names

Requires Python 3.10 or newer. Run from this repository:

```powershell
python "OSINT PYTHON.py" list
python "OSINT PYTHON.py" list --group 6 --json
python "OSINT PYTHON.py" check
python "OSINT PYTHON.py" plan ACADEMICINT --objective "Review the supplied publication records"
python "OSINT PYTHON.py" run ACADEMICINT --input examples/osint140/academic.json --output academic-result.json
```

The example contains explicitly synthetic records. Choose a new output path on each run; existing files are preserved. JSON input must contain a nonempty `case_id` and the fields accepted by the resolved native module. Nested records must belong to the same case. Authorization required by a module must be supplied explicitly; the launcher does not invent it.

For an installed console command:

```powershell
python -m pip install .
traceatlas-osint list --json
traceatlas-osint check
```

## What runs

The ten groups contain all 140 requested names, including OSINT.

| Route type | Requested names | Meaning |
|---|---:|---|
| Exact existing name | 66 | Runs the existing catalog handler |
| Legacy spelling alias | 12 | Uses the existing renamed handler and its input schema |
| Parent discipline | 62 | Uses a broader existing handler; output includes its restricted scope |

The 140 routes currently resolve to 53 supplied-record analysis contracts, 72 planning contracts and 15 unconfigured scope-check contracts. These counts describe routes, not 140 independent collectors. The native suite contains 135 registered modules, including additional names outside the requested taxonomy.

Every result records `requested_discipline`, `canonical_id`, `route_kind`, `execution_mode` and the native `draft_status`. `RETURNED` means the worker returned JSON. A native `BLOCKED_CONFIGURATION` or `BLOCKED_PERMISSION` remains visible and is never converted into successful collection. Live APIs and hosted execution are not qualified by offline tests.

`NETWORKINT` concerns relationships and maps to the relationship handler. `NETINT` concerns network infrastructure. METADATAINT, MOBILEINT and POLICYINT are not equated with similarly spelled measurement, movement or political-intelligence modules.

## Repairs

- Windows no longer fails on the POSIX-only `resource` import. Child audit restrictions and parent wall-clock deadlines remain active. POSIX applies available CPU, memory, file-size and descriptor limits; Windows does not claim those hard limits.
- Worker JSON uses UTF-8 bytes on every platform, preserving Hindi and other non-Latin records even with legacy terminal encodings.
- Numeric overflow such as `1e999`, non-finite numbers, scalar worker reports, malformed input containers and duplicate input JSON keys are rejected.
- Academic approval fields require literal JSON `true`. Cloud and hybrid processing require the module's explicit cloud approval.
- Duplicate publication IDs and normalized DOIs are rejected before they can silently replace an earlier record and its evidence.
- Academic numeric weights cannot turn NaN or infinity into high confidence. Reports retain their limitations.

The maintained Academic module shares its analysis implementation with the recovered source. Its original and stored-source provenance hashes are preserved; the catalog runtime hash changes to identify the repaired code.

The full historical recovery is still available under `extras/osint_module_recovery_20261015`. It contains 136 source segments, duplicated/generic sections and 36 documented incomplete original tails. The archive is preserved as source recovery; it is not evidence that every historical function or live integration has been repaired.

## Validation

GitHub Actions runs the new CLI, taxonomy, Academic and worker regressions plus all 135 native contracts on Windows and Linux with Python 3.10 and 3.12. The normal repository CI also runs. Native GUI checks require a display and are reported as skipped in the platform matrix; the existing Linux/Xvfb job covers those panels.

```powershell
python -m unittest discover -s tests -p "test_osint*.py" -v
python -m unittest discover -s tests -p test_academic_input_integrity.py -v
python -m unittest discover -s tests -p test_intelligence_portability.py -v
python -m unittest discover -s tests/intelligence -p test_contracts.py -v
```

The standalone `run` command returns an analysis draft. For canonical evidence custody, use the existing ArchiveBridge case workflow.
