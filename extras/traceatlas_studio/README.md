# TraceAtlas Studio: Non-invasive Integration

This directory adds the existing TraceAtlas Studio **standalone GUI and 19-domain baseline** to TraceAtlas-Automator without replacing any existing application, managers, employees, skills, configuration or entry points.

## Why 110 checked source pieces?

The verified standalone GUI source is 109,983 lines / 8,252,241 bytes. It is stored in 110 ordered UTF-8 source pieces so GitHub's limited connector upload can deliver it without truncating a single large file. The pieces are **not** individual executables; the deterministic assembler restores the exact original single-file Python program, verified by SHA-256. Do not edit them independently.

**Expected SHA-256**: `9ee8f313baf68aff74f38c8d3a3a01e0ff513789ca5d131880d9da433fa0ba65`

## Install and run

Requires Python 3.10+ (Python 3.11+ recommended). Standard-library web UI.

```bash
python extras/traceatlas_studio/assemble.py --verify
python extras/traceatlas_studio/assemble.py
python extras/traceatlas_studio/TraceAtlas_AllInOne_Studio.py --self-test
python extras/traceatlas_studio/TraceAtlas_AllInOne_Studio.py --open-browser
```

Or run directly through the loader:

```bash
python extras/traceatlas_studio/assemble.py --run -- --self-test
python extras/traceatlas_studio/assemble.py --run -- --open-browser
```

The GUI binds to localhost by default. Do not publish its local bearer URL or bind it to the Internet.

## What this actually includes

- Standalone local investigation GUI/API
- 19 namespaced intelligence domain engines with smoke tests
- SQLite case/evidence/claim ledger
- Manager routing and source/claim checks
- Four opt-in public API adapters
- Compressed, restorable archive of the originally supplied 419,712-line OSINT source

**Important limits:** the original 419k-line mixed source is *archived*, not fully repaired. Of its 82 previously identified sections, 45 had syntax/boundary problems before recovery. Domain smoke tests do **not** certify every historical function. This integration is not a claim of zero bugs or production security readiness.

## Integrity and isolation

No existing TraceAtlas-Automator files were changed by this addition. The assembler checks SHA-256 **before execution**. Running it restores only the named Python file inside this subdirectory. Original code is preserved in the standalone file's embedded archive.

The historical source includes synthetic token-shaped strings in examples. Before any new public release or deployment, independently review the complete source for secrets, privacy, licenses and dependencies.

## Verification

```bash
python extras/traceatlas_studio/assemble.py --verify
python extras/traceatlas_studio/assemble.py --run -- --self-test
```

Existing TraceAtlas-Automator tests and CI must continue to pass unchanged.
