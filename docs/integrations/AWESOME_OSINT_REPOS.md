# Awesome OSINT Repositories: isolated catalogue import

This directory documents the complete, byte-exact integration of the user-supplied `awesome-osint-repos-main.zip` snapshot into TraceAtlas.

## Location and provenance

- Vendored root: `integrations/awesome-osint-repos/`
- Upstream: https://github.com/osintshifu/awesome-osint-repos
- Immutable upstream source commit: `d2cb55dcceb445d45ce08ef58d75c9a6f23daa97`
- Verified ZIP-derived Git tree SHA: `f823ffb73ea4933d7a8130bdf5911c0be0d0dd66`
- Snapshot includes **39 tracked files** (all original source, data, documentation, GUI, tests, and upstream workflow templates).
- Source license: MIT; upstream `LICENSE` is kept with the vendor snapshot.

The integration is intentionally isolated: original `.github/workflows` files remain *nested inside the vendor directory*, so their scheduled GitHub API jobs do not automatically run in TraceAtlas. No core TraceAtlas modules or configuration are overwritten.

## What actually ships

A searchable, **review-gated directory** of 497 linked open-source repositories, taxonomy/candidate data, Python standard-library metadata/discovery scripts, a read-only GUI, and tests. A catalogue entry is a reference, **not** a locally installed or qualified TraceAtlas collector, an available API key, or a live evidence feed. Entries must pass TraceAtlas authorization, adapter qualification, licensing, security and evidence-custody gates before activation.

## Reproducible checks

Run from the TraceAtlas repository root:

```bash
python -m compileall -q integrations/awesome-osint-repos/.catalog/scripts integrations/awesome-osint-repos/.catalog/gui integrations/awesome-osint-repos/tests
python -m unittest discover -s integrations/awesome-osint-repos/tests -v
python integrations/awesome-osint-repos/.catalog/scripts/render_catalog.py --check
python integrations/awesome-osint-repos/.catalog/scripts/validate_catalog.py
node --check integrations/awesome-osint-repos/.catalog/gui/app.js
```

Launch the read-only catalogue independently from the primary TraceAtlas console:

```bash
python integrations/awesome-osint-repos/.catalog/gui/server.py --host 127.0.0.1 --port 4173
```

View `http://127.0.0.1:4173`. This is a separate local-only service, not a multi-tenant TraceAtlas endpoint. Do not expose it externally without access controls and deployment review.

To regenerate static files, run `python integrations/awesome-osint-repos/.catalog/gui/build_static.py`; build output is not tracked.

## Preservation policy

Treat upstream content as a separately versioned dependency. No new workflow may silently refresh the 497 catalogue entries, execute referenced third-party repositories, auto-promote candidate discoveries, or trigger network collection without analyst approval. Changes require provenance verification, tests, review and an explicit sync.
