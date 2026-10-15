# Three uploaded OSINT frameworks: governed TraceAtlas integration

The uploaded ZIP files were audited before this integration:
- \`theHarvester-master.zip\`: 340 ZIP entries; GPL-2.0-only; current pinned upstream requires **Python >=3.14**. Source stored as a separate Git submodule at commit \`49a38f8d33c32336bbf6a111ea723ea223116265\`.
- \`OSINT-SPY-master.zip\`: 17 ZIP entries; GPL-3.0; older third-party dependencies including \`requests==2.22.0\` and \`urllib3==1.25.7\`. Source stored as separate submodule at \`03dcf4868f7a63a2d863996c4bbc62db1c60bc82\`.
- \`Mr.Holmes-master.zip\`: 486 ZIP entries; GPL-3.0; interactive, active scans, subject-based profile/phone collection, SMTP features. Source stored as separate submodule at \`028bffba615c8b95db4cf1babe1b0e5925237eb4\`.

Uploaded root-file Git blob hashes match the referenced official upstream snapshots. The source remains unmodified and follows the original licenses. \`main\` TraceAtlas packaging must **not** silently import/install GPL scripts or their conflicting dependencies as first-party Python modules.

## Capability separation

- **Source:** all three full upstream codebases are available through pinned Git submodules and \`git submodule update --init\`.
- **Execution:** theHarvester already has an existing standalone integration through TraceAtlas \`IntegrationRunner\`, subject to the version-specific Python 3.14 environment and policy gates. This commit does not upgrade, smoke-test, or run it live.
- **OSINT-SPY and Mr.Holmes:** no subprocess execution from TraceAtlas; disabled for network scanning, sensitive identity, credentials, email/phone profiling and unattended interactive workflows.
- **Safe interoperability:** structured exported JSON/JSONL files can be normalized into source-reported DOMAIN/URL observations only. The canonical EvidenceStore and CaseDB preserve a sanitized receipt and offline provenance hash, not original raw outputs which may include private data or keys.

## Setup and offline import

\`\`\`bash
git submodule update --init third_party/theHarvester third_party/OSINT-SPY third_party/Mr.Holmes
PYTHONPATH=src python -m traceatlas.integrations.thirdparty_osint catalog
PYTHONPATH=src python -m traceatlas.integrations.thirdparty_osint review \
  --source theharvester --file authorized-export.jsonl --target example.org
PYTHONPATH=src python -m unittest discover -s tests -p 'test_three_osint_frameworks.py' -v
\`\`\`

For an **existing, already authorized** TraceAtlas \`CaseDB\`, import with the Python API:

\`\`\`python
from pathlib import Path
from traceatlas.integrations.thirdparty_osint import import_file
report = import_file(db, Path("cases"), case_id="existing-case-id",
                     source="theharvester", file_path=Path("export.jsonl"),
                     target="example.org", authorized=True)
\`\`\`

The importer is intentionally offline: it does not contact websites, install packages, execute third-party code, enrich subjects, verify claims or infer source independence. It rejects out-of-scope URLs/domains, discards email addresses and non-domain personal information, and strips all URL query parameters and fragments. Imported domain relationships remain *unverified observations* until independent corroboration.

## Release gates still outstanding

1. Runtime smoke-test theHarvester in its Python 3.14 \`uv\` environment using only authorized test sources.
2. Review each older upstream codebase's licenses, provenance, transitive vulnerabilities and secret leaks, and decide whether a secure separate process can support a narrow non-personal capability.
3. Add data-shape fixtures from approved real exports for OSINT-SPY and Mr.Holmes; input formats vary, and the current importer supports only conservative JSON object keys.
4. Create canonical source identities, provenance independence labels and field-level uncertainty within TraceAtlas evidence pipeline.
5. Container/network sandbox before any newly enabled script execution. Do not treat tests as live-verified results.

Status: **CODED source pinning + offline canonical evidence importer**, **CI TESTED only after green GitHub checks**. No live provider or full-feature-parity claim.

## Upload provenance

Original uploaded ZIP SHA-256 checksums (these ZIP bytes are **not** uploaded as a second copy to GitHub):

- theHarvester-master.zip: `5e6f37c61d1fef3bc800b1bfb1a8403d8c0372ca929e5abf4c0c76d8b0274c8c`
- OSINT-SPY-master.zip: `9fe498ca2f02480fdb2d3e2dda288d793c301782cba807fba7397c2a13175065`
- Mr.Holmes-master.zip: `036c3583597655983665e3e156eecfd5f17b4385465830c7ff1048d883c420e2`

Imported URLs retain only `scheme://hostname/`, because query parameters, fragments and paths may carry sensitive tokens. Existing `integrations list` now shows OSINT-SPY and Mr.Holmes as blocked until individually qualified.
