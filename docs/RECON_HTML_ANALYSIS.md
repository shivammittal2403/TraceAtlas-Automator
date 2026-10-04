# Supplied Recon HTML Analysis

## What the file does

`recon.html` is a client-side searchable directory interface. It provides:

- fifteen visual categories;
- keyword search, category filtering and sorting;
- paginated cards linking to external tools;
- source/category/tool counters;
- responsive presentation.

It does not execute Recon-ng, Amass or any other security tool. At runtime it
fetches this separate URL:

```text
https://raw.githubusercontent.com/shivammittal2403/open-source-intelligence/main/recon-data.json.gz
```

The HTML's embedded `tool-data` array is `[]`. During the integration review,
the referenced remote dataset returned HTTP 404, so the actual directory
records could not be recovered from this attachment.

## Integration decision

TraceAtlas therefore separates two concerns:

1. **Executable registry** — individually verified CLI adapters with target,
   safety, parsing and evidence contracts.
2. **Research catalog** — arbitrary directory entries imported from JSON,
   JSON.GZ or embedded HTML and searchable without execution.

When the missing dataset is restored, import it with:

```bash
traceatlas integrations catalog-import --file recon-data.json.gz
```

This architecture can retain every directory entry without pretending that a
website, commercial portal, mobile app, browser extension or reference page is
a locally executable scanner.

