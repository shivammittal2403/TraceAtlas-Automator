# TraceAtlas 136-section recovered OSINT source

This is an **opt-in recovered source bundle** under `extras/traceatlas_136_repair/`. It does **not** overwrite the existing TraceAtlas-Automator orchestrator, AI employees, skill files, services, or CI configuration. It is separate from the older TraceAtlas Studio PR #87.

## What is here

- **136 isolated recovered Python sections** from a concatenated 419,712-line source. Section count does *not* prove 136 distinct AI employees.
- Source-repair fixes for malformed syntax, import-time dataclasses/enums, and fixture-runtime errors.
- `manifest.json`, per-section source origin, `reports/` with original recorded tests, and `quarantine/` holding source portions not recovered into executable modules.
- **Original upload** preserved byte for byte inside the verified archive.
- A compact compressed package stored in 81 immutable ordered base64 Git objects because the GitHub connector cannot upload the original large binary directly. `assemble.py` reconstructs and verifies the source. Never execute `.b64` parts as scripts.

## Restore or run

From the root of the repository:

```bash
python extras/traceatlas_136_repair/assemble.py verify
python extras/traceatlas_136_repair/assemble.py extract --to ./traceatlas_recovered_source
python traceatlas_recovered_source/traceatlas.py verify
python traceatlas_recovered_source/traceatlas.py list
python traceatlas_recovered_source/traceatlas.py sample 18
```

Or run without a permanent extraction:

```bash
python extras/traceatlas_136_repair/assemble.py run -- verify
python extras/traceatlas_136_repair/assemble.py run -- list
```

Python 3.11+ recommended. The installer is stdlib-only and checks the package SHA-256 and original source SHA-256 before extracting or launching anything. The extraction target must not already exist.

## Measured claims, not marketing

- **136/136 Python compile gates** and **136/136 isolated imports** passed in the local source-repair audit.
- **33/33 invoked argument-free sample fixtures** passed; 2 require input arguments; 101 sections do not have a validated sample entrypoint.
- **36 segments were recovered only partially.** Their omitted source text is quarantined and archived, not silently replaced.
- **No real provider/API canaries or end-to-end production investigations** were verified. Do **not** advertise this as a 136-employee live platform or Maltego-equivalent product yet.

The GitHub PR is intended for code review and reproducible isolated verification. Nothing imports this bundle automatically into the existing application.

## Package SHA-256

- Repaired bundle TAR.XZ: `a26b7730cd17748866024e03304c0560f386addf50ec58c4ba333bd3e2ff686b`
- Original `OSINT PYTHON.py`: `5a5f51623f7ad13b0a40b12dcb05110da20262c1ae9d387bed290cd44555add5`

## Security and release review

Public repository: this bundle contains public training-style synthetic key-shaped examples as well as the original code. Review all sources for sensitive material and third-party licensing before merging/deploying. Workflows are offline by default; do not feed unauthorized personal or private data into any investigation engine.
