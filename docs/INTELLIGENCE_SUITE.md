# Supplied intelligence suite

The `OSINT all (2)(1).zip` upload is integrated additively. All 136 members are
retained under `packages/archive_sources/intelligence-suite`, with inert
`.source` extensions. Potential credential-shaped sample strings in two source
files are redacted. Original and stored hashes remain distinct in the manifest.
The maintained, importable copies of all 135 Python modules are under
`traceatlas.addons.intelligence_v1.modules`. Existing case/evidence stores,
worker admission controls, source allowlists, hosted RLS and legacy panels
remain canonical.

## What runs

| Entry mode | Modules | Meaning |
| --- | ---: | --- |
| Supplied-record analysis | 68 | A named function/employee/request/journal consumes submitted records. Outputs remain drafts. |
| Planning only | 53 | A collection plan or panel planning helper runs. It does not collect data. |
| Unconfigured scope check | 14 | The upload pipeline accepts its typed case contract and reports `BLOCKED_CONFIGURATION`. |

These are **135 module entry points, not 135 working live-source integrations**.
Provider access, licensed social/breach/threat intelligence, hosted operation,
analyst outcomes and vendor parity are not established by this import.
Successful empty-input invocation is a smoke test, not deep feature validation.

## Canonical case review

Install the package through the existing setup workflow. Then list the fixed
contracts and create an isolated case:

```bash
traceatlas archive modules
traceatlas --workspace cases init case-one --title "Submitted records" --purpose "Approved local review"
traceatlas --workspace cases archive analyze --case case-one --action intelligence --input review.json --authorized
```

Example `review.json`:

```json
{
  "module": "bioint",
  "input": {
    "objective": "Review supplied research metadata",
    "research_records": [
      {
        "record_id": "R-1",
        "record_type": "PUBLIC_RESEARCH",
        "source_id": "submitted-record-1",
        "publication_date": "2026-01-01",
        "method": "Literature review",
        "limitations": ["Source authenticity needs independent review"]
      }
    ]
  },
  "evidence_ids": ["@input"]
}
```

`input` follows the chosen module's existing contract; the catalog names its
entry point and execution mode. Typed request/pipeline adapters reject unknown
fields. Journal adapters accept named collections such as `records.evidence`
and `records.transactions`, using the corresponding module's declared methods.
Module-specific synthetic contract examples are in `tests/intelligence/fixture_inputs.py`.

`--authorized` approves processing this submitted file only. The adapter derives
local processing metadata from that check; callers cannot insert `authorization`,
credentials, permissions, tenant identifiers or another case's citations. A
module's embedded policy object never grants canonical authority. Nested
`case_id` values must match the current case. Sample/demo corpora cannot become
case evidence. Existing citations must already belong to the verified case.
Imported engine evidence identifiers remain source-local labels; the outer
review's canonical `evidence_ids` identify the preserved input and verified case
citations. No engine confidence or `supported_facts` label becomes a canonical
verified fact automatically.

The byte snapshot, draft finding and custody receipt use the existing
`ArchiveBridge`, `CaseDB` and `EvidenceStore`. Failed input validation, child
execution, deadlines or invalid output produce no new evidence. Repeated
identical review is idempotent in the same case, even when an imported engine
generates fresh UUIDs or timestamps. The retained first draft is returned.
Canonical draft identity includes the case, submitted bytes, module hash,
runtime/adapter/contract profile and Python version; a changed profile produces
a separate review. The existing SQLite uniqueness constraints enforce this
without a schema migration. This does not qualify crash recovery or hosted jobs.

## Execution boundaries

Only hash-pinned catalog entry points execute, in a separate Python process
with an empty provider environment, CPU/address-space/file limits, a deadline,
and finite JSON/report limits. Audit hooks reject network, child process,
database and external file access. These controls are defense in depth for the
reviewed bundled modules; **they are not an OS sandbox for arbitrary plugins**.
This records-only adapter does not graduate file-path loaders, media subprocesses
or provider connectors. Existing standalone media functionality has its own
fixture tests and requires its local dependencies and approved artifacts.

Runtime execution currently requires a POSIX environment providing `resource`;
missing runtime/optional Tk dependencies are explicit failures, not silent
provider fallbacks. Python core installation still has no third-party runtime
dependencies. Native panels require Tk; media panels also require their existing
Pillow/FFmpeg dependencies.

## Optional native panels

```bash
python -m traceatlas.addons.intelligence_v1 catalog
python -m traceatlas.addons.intelligence_v1 gui socmint
```

The catalog lists each available `gui_entry`. This explicitly starts the chosen
existing panel. The canonical offline review path remains the case-bound CLI
above. The older nine maintained panels are reused rather than overwritten by
the upload's buggy copies. Archive-only and prototype source catalogs are not
reported as verified provider integrations.

## Repairs and verification

Repairs remove interrupted duplicate copies and incomplete demonstration tails,
correct syntax/indentation, enum members, dataclass ordering, malformed regexes,
missing helpers and null handling. PACKAGEINT's interrupted pipeline is completed
using its existing ingestion, dependency, advisory, contradiction and handoff
functions. BIOINT's empty upload receives a bounded metadata-completeness review.
Original fragments remain available in the inert snapshots.

```bash
PYTHONPATH=src python -m unittest discover -s tests -q
PYTHONPATH=src python -m unittest discover -s tests/intelligence -v
python scripts/verify_intelligence_suite.py
python scripts/check_python_structure.py
python scripts/check_secrets.py
uvx ruff check --select F821,F822,F823 src/traceatlas/addons/intelligence_v1
xvfb-run -a env PYTHONPATH=src /usr/bin/python3 -m unittest discover -s tests/intelligence -v
```

Core negatives cover case/citation isolation, embedded authority and secrets,
sample substitution, malformed/oversized input, source tampering, timeout,
non-finite/oversized output, child restrictions and failure atomicity. Repair
regressions exercise nonempty research metadata, package advisory mapping,
linguistic duplicates/negation, preserved TTP conflicts and IOC namespace regexes.
All-module invocations and native initialization are separate optional tests.
Without a display, native tests are explicitly skipped; CI runs them with Xvfb.
