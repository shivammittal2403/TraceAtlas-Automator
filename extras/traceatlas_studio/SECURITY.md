# TraceAtlas Studio integration security note

This integration is intentionally opt-in, added under `extras/traceatlas_studio/`. It does not replace TraceAtlas-Automator's existing managers, services, employee modules or dependencies.

- Web UI/API are localhost-only with a runtime bearer token.
- External API calls must be explicitly enabled in the standalone application.
- Do not publish GUI token URLs, evidence files or private cases.
- The embedded source archive can restore the originally uploaded 419,712-line source.
- Source archives may include **synthetic token-shaped fixtures**. Perform repository-wide secret checks before deployment or republishing.
- The 82 additional original sections are **not** all runtime-verified.
- Run the SHA-256 verification and independent end-to-end tests before enabling integrations.
