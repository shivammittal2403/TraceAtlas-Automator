# Local investigation runbook

```bash
git clone --recurse-submodules https://github.com/shivammittal2403/TraceAtlas-Automator.git
cd TraceAtlas-Automator
./set.sh
export TRACEATLAS_WORKFORCE_ENABLED=1
./start.sh init demo-case --title "Controlled review" --purpose "Authorized source-record review"
./start.sh workforce authorize --case demo-case --target-type domain --target example.org   --actor analyst-1 --purpose "Authorized controlled public-record review" --jurisdiction IN --authorized
# Use returned AUTH_ID, TASK_ID and DIGEST literally in the subsequent commands.
./start.sh workforce plan --context AUTH_ID --target-type domain --target example.org   --objective "Review authorized public source assertions and remaining unknowns"
./start.sh workforce approve --task TASK_ID --actor analyst-1 --envelope-digest DIGEST   --rationale "Reviewed exact seed, scope and permitted source budget" --authorized
./start.sh workforce run --task TASK_ID --documents source-records.json --authorized
./start.sh workforce report --task TASK_ID
./start.sh workforce replay --task TASK_ID
./start.sh workforce golden
```

`source-records.json` is an array of strict SourceDocument objects; see
`schemas/source-document.schema.json` and the synthetic packaged golden records.
For actual domain/IP/CVE/vulnerability/package provider collection use `--live` instead of
`--documents`. The example domain is a documentation seed, not an ownership
attestation for a real investigation. Person/company targets are case-local
public IDs and accept records only. CLI output contains the draft Markdown,
evidence references, graph/timeline, verification and replay metadata.

Exact security-metadata example:

```bash
./start.sh workforce authorize --case demo-case --target-type cve --target CVE-2024-12345 \
  --actor analyst-1 --purpose "Authorized vulnerability review" --jurisdiction IN --authorized
./start.sh workforce plan --context AUTH_ID --target-type cve --target CVE-2024-12345 \
  --objective "Review advisory severity and exploitation probability"
# Approve the returned digest, then run with --live as above.
```

Use `vulnerability` for an exact OSV/GHSA identifier and `package` for an exact
npm name, including `@scope/package`. Results require human comparison with
authorized asset or software inventory.

Set `TRACEATLAS_WORKFORCE_KILL_SWITCH=1` to stop new dispatch. On provider failure
inspect source_outcomes/gaps; do not interpret missing results as absence. On
expired authority create fresh authority and a new task. On failed replay retain
files for review; never bypass byte/digest/custody checks. Reports remain drafts.

Live source setup, explicit source selection and credential references are in
[LIVE_SOURCES.md](LIVE_SOURCES.md). Run `workforce sources` before planning;
configure search before registering authority so `search.execute` is permitted.
Use `plan --sources ...` to bind your intended connectors, approve its digest,
then `run --live`. Source failure and unknown provider costs remain in the product.
