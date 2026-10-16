# Actual tracked copies for four small reconnaissance projects

These four directories hold 36 ordinary Git-tracked upstream source files, not submodule pointers:

- assetfinder (MIT; 16 files)
- hakrevdns (MIT; 3 files)
- cero (MIT; 13 files)
- CTFR (GPL-3.0; 4 files)

Each file is byte-identical to the pinned upstream Git blob and verified by tests/test_extreme_recon_vendored.py against docs/integrations/EXTREME_RECON_VENDORED.json. Each original LICENSE is included. This code is SOURCE-ONLY, not imported into TraceAtlas or authorized to execute.

The other 29 newly pinned GitHub projects are **submodule references**, not directly tracked source files. theHarvester was already vendored in vendor_sources/theHarvester. Full duplication of the largest projects would expand the repository substantially and requires project-specific license/security review and controlled source export.

Reading code is not the same as a production-ready investigation provider. Use TraceAtlas's existing canonical IntegrationRunner authorization gates for the already supported tools.
