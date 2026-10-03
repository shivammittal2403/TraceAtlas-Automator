# TraceAtlas engineering cycle — 2026-10-03

## Repository State

Refreshed clean main at `fe51ba7b2e085038751a0de1fb546a2ec8453397`. Requested
`2a8789eb7cc401b327796e32458b9733674ecbc9` is its historical ancestor. Preserve
40 subsequent changed files and existing workforce/control-plane integrations.
Baseline GitHub CI and CodeQL both passed. The local checkout needed the pinned
OpenCTI submodule; workforce fixtures also contained authority expiring 1 October.

## What Was Verified

Existing canonical owners, manifests, docs, test/build/CI definitions, local
policy/evidence/graph/model/connector boundaries and the blueprint delivery
ledger. Runtime evidence is distinct from catalog/UI/documentation existence.
`docs/GAP_ANALYSIS.md` records the pre-change capability and security gaps.

## Architecture Decisions

Retain Python standard library, SQLite, EvidenceStore, existing fixed-host HTTPS
providers, plain JavaScript and existing hosted control plane. Extend workforce;
do not create a new agent core or replace technologies. Model count/tokens/spend
for the new slice: zero. Use deterministic structured-source validation and abstain
from unverified text semantics. Preserve identity ambiguity and source uncertainty.

## Implementation Plan

Audit and gap record first; repair authority/digest/lineage boundaries; integrate
one bounded capture/analysis cycle; persist draft/replay; run controlled
investigations and regressions; synchronize requested docs; publish through GitHub
with CI/CodeQL before release/promotion.

## Changes Implemented

1. Typed seed/strict source document/fact contracts and source input JSON Schema.
2. Scoped approved-record Person/Company and fixed-host Domain/IP collection paths.
3. Acquisition-aware immutable captured bytes and v2 metadata, preserving v1 imports.
4. Observations, structured claims, transitive source-lineage components, verified
   source assertions, explicit INCONCLUSIVE text extraction and temporal conflicts.
5. Source/Evidence/Observation/Claim provenance graph, individual validity edges,
   timeline, unknowns and rule-ranked next checks without autonomous identity merging.
6. Immutable draft, versioned replay manifest, byte/custody/digest-checked offline
   reanalysis; atomic local result/product/terminal task writes.
7. Current authority/deadline/kill checks, exact capability routing, acquisition
   binding, nested tool-secret rejection and shared network-attempt ceilings.
8. Concrete authorize/plan/run/report/replay/golden CLI and G01–G12 controlled pack.
9. Date-independent authority fixture, negative regressions and CI golden gate.

## Files Changed

Core owners: `workforce/documents.py`, `pipeline.py`, `service.py`, `store.py`,
`registry.py`, `lineage.py`, `verification.py`, `tools.py`, `graph.py`, `cli.py`,
`golden.py` and packaged golden data. Tests: `test_investigation_pipeline.py`,
`test_ai_workforce.py`. CI adds a complete workforce golden step. Root and
requested docs/schema/current-state/gap/security/report artifacts are synchronized.
Existing hosted API/SQL and UI files are not modified. GitHub diff is the exact
file-level review surface; no real-case databases/evidence are committed.

## Tests Actually Executed

- `PYTHONPATH=src python -m unittest discover -s tests -q`
- `node --test tests/test_graph_model.cjs tests/test_target_validation.cjs tests/test_database.mjs`
- `python scripts/verify_delivery.py --output <fresh temporary directory>`
- `python -m traceatlas workforce golden`; actual CLI init/authorize/plan/approve/run/report/replay
- Existing AI evidence-contract benchmark; OpenCTI integrity verification
- Source compilation, shell/JavaScript syntax, secret scan and diff whitespace checks
- Wheel build and inspection of packaged 12-case data
- Existing Playwright browser suite attempted; Chromium installation attempted

## Test Results

237 Python tests pass, 26 combined Node/PGlite tests pass, G01–G12 pass, CLI
end-to-end/replay pass, 8/8 existing AI output-contract cases pass, local evidence
bundle and SQLite restore pass, 8,275 pinned connector files verify, wheel builds.
Nine delivery verification gates pass. Browser testing locally is blocked:
Chromium download returned an invalid/truncated ZIP. Do not report a local browser
pass. The first published implementation commit `c6adcc73f368f416fb778e18c9cdb4e094eb28cc`
passed remote CI and both CodeQL analyses. CI passed Python 3.10/3.12 core jobs,
including the real Chromium synthetic browser flow, worker image, package/SBOM,
dependency review and preserved OpenOSINT runtime. This resolves browser
verification in CI; it does not claim a local browser pass or live provider proof.
Subsequent documentation/worker-version publication requires its own CI result.
Compact evidence is `docs/verification/2026-10-03.json`.

## Security Review

Confirmed local authorization/kill/routing/lineage/reference/semantic-extraction
weaknesses were remediated with negative tests. Source text cannot grant tool
permissions. Hosted read/approve API and RLS compatibility were reviewed with the
existing isolation tests; no new hosted grants/migration. See SECURITY_REVIEW.md
for evidence, preconditions and residual limits. This is a limited changed-path
review, not an independent security certification.

## Performance/Cost Impact

No new runtime dependency or model spend. Capture caps at eight 512 KiB source
documents; structured projections cap at 200 facts; network attempts including
retries cap at eight and share a 120-second task ceiling. Source grouping is
bounded pairwise comparison, not unbounded swarm recursion. Storage/CPU/egress
cost and production latency/SLOs are not measured. Local 237-test suite runs in
about four seconds; this is test-runtime evidence, not investigator throughput.

## Documentation Updated

Gap/current state/architecture/workflow/user flow/feature/use-case/contract/API/
worker/model/domain/evidence/entity/graph/timeline/verification/gap/action/security/
privacy/cost/observability/test/evaluation/deployment/runbook/recovery/roadmap/change
control documentation now describes actual implementations and planned gaps.
Existing historical blueprint/workforce assessments remain available.

## Known Limitations

One deterministic collection cycle, no objective-driven semantic autonomous
planner or independent adversarial search. Person/company are approved-record
modes. Structured export corroboration establishes captured source assertions,
not author identity or objective truth. RDAP bootstrap redirects remain blocked.
New runner is local only; hosted UI/private-worker integration is absent.
Replay requires original/restored workspace paths. Capture is not transactional
with every derived write; failed-task resume/cancel/checkpointing is not added.

## Remaining Gaps

Approved live search and vetted RDAP routing; real provider licensing/source
quality; held-out semantic/model/identity evaluation; hosted Auth/JWT/RLS/storage/
concurrency/recovery/load/pilot; product UI; durable orchestration/cost reservations;
full CTI/malware/isolation/DARKINT/BOM/country/dataset domain slices. G05–G08 are
shared-backbone fixtures, not complete specialized engines. Production acceptance
and Maltego/Social Links parity remain unestablished.

## Next Highest-Value Task

Qualify a vetted RDAP bootstrap destination policy and one approved search
adapter with preserved bytes, then connect this canonical product to a private
hosted worker and the investigator evidence/claim view with staging isolation
and recovery proof.
