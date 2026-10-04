# OpenCTI Connectors Source Snapshot

- Origin: `OpenCTI-Platform/connectors`
- Input archive SHA-256: `dfefff461b0e5718c0455bd890cde0b54d077c361cec8d4c97a0f08658c43452`
- Pinned upstream commit: `55ca0dfa4129050cb607fdaf6b1a7457e0ae3476`
- Pinned upstream tree: `4cf99829246e13b640f6d4fd2ffd6580194d0116`
- Extracted files before TraceAtlas notices: 8,275
- Connector packages: 308
- Default upstream license: Apache-2.0
- Folder overrides: four AGPL-3.0-only packages and one MIT package
- Reproducibility: the supplied files matched the pinned tree byte for byte except
  for 19 credential-shaped public upstream test/documentation fixtures that were
  sanitized during review; the committed submodule preserves the authoritative
  upstream revision.

This submodule is third-party source, not code authored by TraceAtlas.
The upstream and folder-specific license files remain authoritative. TraceAtlas
adds a service-boundary registry and never enables these connectors by default.
Run `git submodule update --init --depth 1` to materialize the complete source;
`./setup.sh` and `./start.sh` do this automatically when Git is available.
