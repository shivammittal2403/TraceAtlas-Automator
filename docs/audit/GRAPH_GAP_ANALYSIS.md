# Graph gap analysis

Baseline: `641f159326d45afe9797ddf5624a5126640fdd19`, 2026-10-04.

## State

**IMPLEMENTED / TESTED:** in-memory temporal nodes/edges with evidence and observation references; browser parser/filters, path inspection and case graph APIs; PR #44 closed caller-supplied acceptance of sensitive identity/causation edges. Human identity decisions remain in ResolutionService.

**PARTIAL:** graph is not a persistent investigator-grade temporal analytics workspace. Current implementation does not demonstrate broad k-hop expansion, community detection, centrality/bridge metrics, temporal paths, neighborhood comparison, snapshot diffs, collaboration, or large-graph case usability end-to-end. Existing graph rendering has bounded node/edge limits.

## Rules and next work

Graph algorithms produce leads, never facts. Every edge needs source/evidence, time, confidence basis, uncertainty, status and contradiction access. Keep candidate social/infrastructure edges distinct from verified facts and identity truth. A Maltego-class claim requires useful transforms/capability execution, case persistence, provenance navigation, temporal analysis, filtering, scale and repeatable analyst usability tests. Graph implementation alone does not meet that gate.
