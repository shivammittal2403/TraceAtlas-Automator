# Media and evidence fusion

TraceAtlas 1.0 combines deterministic local media checks with a transparent
candidate board. It is designed for consented, organisation-owned and public
interest research—not covert person tracking.

## Local verification

`intel media` validates common image signatures, records SHA-256, preserves the
source in the evidence ledger and, when Pillow is installed, computes aHash and
dHash for near-duplicate triage. Perceptual hashes are similarity hints; they do
not prove that two images share an origin. EXIF coordinates continue to be
stored only at two-decimal precision.

```bash
./start.sh intel media --case demo-001 --file evidence.jpg \
  --owned-asset --authorized --ocr
```

## Fusion Board input

The board accepts JSON or JSONL records:

```json
{
  "candidate": "candidate label",
  "source": "exiftool",
  "signal": "embedded GPS observed",
  "evidence": "sha256:...",
  "classification": "observed",
  "confidence": 95,
  "supports": true,
  "latitude": 28.6139,
  "longitude": 77.2090
}
```

`classification` is `observed`, `inference` or `model-output`. Inferences and
model outputs receive explicit score discounts. Repeated claims from one source
are capped so a single provider cannot manufacture consensus. Opposing records
are retained under `contradictions` rather than silently averaged away.

```bash
./start.sh fusion rank --case demo-001 --file signals.json \
  --scope location --owned-asset --authorized

./start.sh fusion geojson --case demo-001 \
  --file cases/fusion/demo-001/signals-location.ranked.json \
  --output reports/location-candidates.geojson --owned-asset --authorized
```

Identity ranking requires subject consent. Location ranking requires consent or
asset ownership. Organisation and infrastructure ranking require organisation
ownership. GeoJSON contains coarse coordinates only.

## Document and geospatial MCPs

Local files cannot be passed directly into Citra, Docling or GeoAI. Stage each
file first; this validates size, extension, content signature and ownership,
rejects symlinks, and creates an evidence record.

```bash
./start.sh capabilities stage-file --case demo-001 --file report.pdf \
  --owned-org --authorized

./start.sh capabilities mcp-call --case demo-001 --source citra \
  --tool read_pdf --arguments-file read-pdf.json --owned-org --authorized
```

Only the returned staged path is accepted. Document-generation/destructive MCP
tools and GeoAI imagery-download tools are not allowlisted.
